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

#ifndef	_LIBADUTILS_H
#define	_LIBADUTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <ldap.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ADUTILS_DEF_NUM_RETRIES	2
#define	ADUTILS_SID_MAX_SUB_AUTHORITIES	15
#define	ADUTILS_MAXBINSID\
	(1 + 1 + 6 + (ADUTILS_SID_MAX_SUB_AUTHORITIES * 4))
#define	ADUTILS_MAXHEXBINSID	(ADUTILS_MAXBINSID * 3)

typedef struct adutils_ad adutils_ad_t;
typedef struct adutils_entry adutils_entry_t;
typedef struct adutils_result adutils_result_t;
typedef struct adutils_ctx adutils_ctx_t;
typedef struct adutils_query_state adutils_query_state_t;

/*
 * Typedef for callback routine for adutils_lookup_batch_start.
 * This callback routine is used to process the result of
 * ldap_result(3LDAP).
 *	ld   - LDAP handle used by ldap_result(3LDAP)
 *	res  - Entry returned by ldap_result(3LDAP)
 *	rc   - Return value of ldap_result(3LDAP)
 *	qid  - Query ID that corresponds to the result.
 *	argp - Argument passed by the caller at the time
 *	       of adutils_lookup_batch_start.
 */
typedef void (*adutils_ldap_res_search_cb)(LDAP *ld, LDAPMessage **res,
	int rc, int qid, void *argp);

typedef enum {
	ADUTILS_SUCCESS = 0,
	ADUTILS_ERR_INTERNAL = -10000,
	ADUTILS_ERR_OTHER,
	ADUTILS_ERR_NOTFOUND,
	ADUTILS_ERR_RETRIABLE_NET_ERR,
	ADUTILS_ERR_MEMORY,
	ADUTILS_ERR_DOMAIN
} adutils_rc;

/*
 * We use the port numbers for normal LDAP and global catalog LDAP as
 * the enum values for this enumeration.  Clever?  Silly?  You decide.
 * Although we never actually use these enum values as port numbers and
 * never will, so this is just cute.
 */
typedef enum adutils_ad_partition {
	ADUTILS_AD_DATA = 389,
	ADUTILS_AD_GLOBAL_CATALOG = 3268
} adutils_ad_partition_t;


/*
 * adutils interfaces:
 *
 *  - an adutils_ad_t represents an AD partition
 *  - a DS (hostname + port, if port != 0) can be added/removed from an
 *  adutils_ad_t
 *  - an adutils_ad_t can be allocated, ref'ed and released; last release
 *  releases resources
 *
 *
 * adutils_lookup_batch_xxx interfaces:
 *
 * These interfaces allow the caller to batch AD lookup requests. The
 * batched requests are processed asynchronously. The actual lookup
 * is currently implement using libldap's ldap_search_ext(3LDAP) and
 * ldap_result(3LDAP) APIs.
 *
 *	Example:
 *      	adutils_query_state_t	*qs;
 *      	adutils_lookup_batch_start(..., &qs);
 *		for each request {
 *			rc = adutils_lookup_batch_add(qs, ...);
 *			if (rc != success)
 *				break;
 *		}
 *		if (rc == success)
 *			adutils_lookup_batch_end(&qs);
 *		else
 *			adutils_lookup_batch_release(&qs);
 *
 *	The adutils_lookup_batch_start interface allows the caller to pass
 *	in a callback function that's invoked when ldap_result() returns
 *	LDAP_RES_SEARCH_RESULT and LDAP_RES_SEARCH_ENTRY for each request.
 *
 *	If no callback is provided then adutils batch API falls back to its
 *	default behaviour which is:
 *		For LDAP_RES_SEARCH_ENTRY, add the entry to the entry set.
 *		For LDAP_RES_SEARCH_RESULT, set return code to
 *			ADUTILS_ERR_NOTFOUND if the entry set is empty.
 *
 *	See $SRC/cmd/idmap/idmapd/adutils.c for an example of
 *      non-default callback routine.
 *
 */

extern adutils_rc	adutils_ad_alloc(adutils_ad_t **new_ad,
				const char *default_domain,
				adutils_ad_partition_t part);
extern void		adutils_ad_free(adutils_ad_t **ad);
extern adutils_rc	adutils_add_ds(adutils_ad_t *ad,
				const char *host, int port);
extern adutils_rc	adutils_add_domain(adutils_ad_t *ad,
				const char *domain_name,
				const char *domain_sid);
extern void		adutils_set_log(int pri, bool_t syslog,
				bool_t degraded);
extern void		adutils_freeresult(adutils_result_t **result);
extern adutils_rc	adutils_lookup(adutils_ad_t *ad,
				const char *searchfilter,
				const char **attrs, const char *domain,
				adutils_result_t **result);
extern char		**adutils_getattr(const adutils_entry_t *entry,
				const char *attrname);
extern const adutils_entry_t	*adutils_getfirstentry(
					adutils_result_t *result);
extern int		adutils_txtsid2hexbinsid(const char *txt,
				const uint32_t *rid,
				char *hexbinsid, int hexbinsidlen);
extern char		*adutils_bv_name2str(BerValue *bval);
extern char		*adutils_bv_objsid2sidstr(BerValue *bval,
				uint32_t *rid);
extern void		adutils_reap_idle_connections(void);
extern char		*adutils_dn2dns(const char *dn);
extern adutils_rc	adutils_lookup_batch_start(adutils_ad_t *ad,
				int nqueries,
				adutils_ldap_res_search_cb ldap_res_search_cb,
				void *ldap_res_search_argp,
				adutils_query_state_t **state);
extern adutils_rc	adutils_lookup_batch_add(adutils_query_state_t *state,
				const char *filter, const char **attrs,
				const char *edomain, adutils_result_t **result,
				adutils_rc *rc);
extern adutils_rc	adutils_lookup_batch_end(
				adutils_query_state_t **state);
extern void		adutils_lookup_batch_release(
				adutils_query_state_t **state);
extern const char	*adutils_lookup_batch_getdefdomain(
				adutils_query_state_t *state);
extern int		adutils_lookup_check_domain(
				adutils_query_state_t *state,
				const char *domain);
extern int		adutils_lookup_check_sid_prefix(
				adutils_query_state_t *state,
				const char *sid);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBADUTILS_H */
