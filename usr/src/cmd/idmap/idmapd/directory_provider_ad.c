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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Retrieve directory information for Active Directory users.
 */

#include <ldap.h>
#include <lber.h>
#include <pwd.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <libadutils.h>
#include <libuutil.h>
#include <note.h>
#include <assert.h>
#include "directory.h"
#include "directory_private.h"
#include "idmapd.h"
#include <rpcsvc/idmap_prot.h>
#include "directory_server_impl.h"

/*
 * Information required by the function that handles the callback from LDAP
 * when responses are received.
 */
struct cbinfo {
	const char * const *attrs;
	int nattrs;
	directory_entry_rpc *entry;
	const char *domain;
};

static void directory_provider_ad_cb(LDAP *ld, LDAPMessage **ldapres, int rc,
    int qid, void *argp);
static void directory_provider_ad_cb1(LDAP *ld, LDAPMessage *msg,
    struct cbinfo *cbinfo);
static directory_error_t bv_list_dav(directory_values_rpc *lvals,
    struct berval **bv);
static directory_error_t directory_provider_ad_lookup(
    directory_entry_rpc *pent, const char * const * attrs, int nattrs,
    const char *domain, const char *filter);
static directory_error_t get_domain(LDAP *ld, LDAPMessage *ldapres,
    char **domain);
static directory_error_t directory_provider_ad_utils_error(char *func, int rc);

#if	defined(DUMP_VALUES)
static void dump_bv_list(const char *attr, struct berval **bv);
#endif

#define	MAX_EXTRA_ATTRS	1	/* sAMAccountName */

/*
 * Add an entry to a NULL-terminated list, if it's not already there.
 * Assumes that the list has been allocated large enough for all additions,
 * and prefilled with NULL.
 */
static
void
maybe_add_to_list(const char **list, const char *s)
{
	for (; *list != NULL; list++) {
		if (uu_strcaseeq(*list, s))
			return;
	}
	*list = s;
}

/*
 * Copy a counted attribute list to a NULL-terminated one.
 * In the process, examine the requested attributes and augment
 * the list as required to support any synthesized attributes
 * requested.
 */
static
const char **
copy_and_augment_attr_list(char **req_list, int req_list_len)
{
	const char **new_list;
	int i;

	new_list =
	    calloc(req_list_len + MAX_EXTRA_ATTRS + 1, sizeof (*new_list));
	if (new_list == NULL)
		return (NULL);

	(void) memcpy(new_list, req_list, req_list_len * sizeof (char *));

	for (i = 0; i < req_list_len; i++) {
		const char *a = req_list[i];
		/*
		 * Note that you must update MAX_EXTRA_ATTRS above if you
		 * add to this list.
		 */
		if (uu_strcaseeq(a, "x-sun-canonicalName")) {
			maybe_add_to_list(new_list, "sAMAccountName");
			continue;
		}
		/* None needed for x-sun-provider */
	}

	return (new_list);
}

/*
 * Retrieve information by name.
 * Called indirectly through the Directory_provider_static structure.
 */
static
directory_error_t
directory_provider_ad_get(
    directory_entry_rpc *del,
    idmap_utf8str_list *ids,
    char *types,
    idmap_utf8str_list *attrs)
{
	int i;
	const char **attrs2;
	directory_error_t de = NULL;

	/*
	 * If we don't have any AD servers handy, we can't find anything.
	 * XXX: this should be using our DC, not the GC.
	 */
	if (_idmapdstate.num_gcs < 1) {
		return (NULL);
	}

	RDLOCK_CONFIG()

	/* 6835280 spurious lint error if the strlen is in the declaration */
	int len = strlen(_idmapdstate.cfg->pgcfg.default_domain);
	char default_domain[len + 1];
	(void) strcpy(default_domain, _idmapdstate.cfg->pgcfg.default_domain);

	UNLOCK_CONFIG();

	/*
	 * Turn our counted-array argument into a NULL-terminated array.
	 * At the same time, add in any attributes that we need to support
	 * any requested synthesized attributes.
	 */
	attrs2 = copy_and_augment_attr_list(attrs->idmap_utf8str_list_val,
	    attrs->idmap_utf8str_list_len);
	if (attrs2 == NULL)
		goto nomem;

	for (i = 0; i < ids->idmap_utf8str_list_len; i++) {
		char *vw[3];
		int type;

		/*
		 * Extract the type for this particular ID.
		 * Advance to the next type, if it's there, else keep
		 * using this type until we run out of IDs.
		 */
		type = *types;
		if (*(types+1) != '\0')
			types++;

		/*
		 * If this entry has already been handled, one way or another,
		 * skip it.
		 */
		if (del[i].status != DIRECTORY_NOT_FOUND)
			continue;

		char *id = ids->idmap_utf8str_list_val[i];

		/*
		 * Allow for expanding every character to \xx, plus some
		 * space for the query syntax.
		 */
		int id_len = strlen(id);
		char filter[1000 + id_len*3];

		if (type == DIRECTORY_ID_SID[0]) {
			/*
			 * Mildly surprisingly, AD appears to allow searching
			 * based on text SIDs.  Must be a special case on the
			 * server end.
			 */
			ldap_build_filter(filter, sizeof (filter),
			    "(objectSid=%v)", NULL, NULL, NULL, id, NULL);

			de = directory_provider_ad_lookup(&del[i], attrs2,
			    attrs->idmap_utf8str_list_len, NULL, filter);
			if (de != NULL) {
				directory_entry_set_error(&del[i], de);
				de = NULL;
			}
		} else {
			int id_len = strlen(id);
			char name[id_len + 1];
			char domain[id_len + 1];

			split_name(name, domain, id);

			vw[0] = name;

			if (uu_streq(domain, "")) {
				vw[1] = default_domain;
			} else {
				vw[1] = domain;
			}

			if (type == DIRECTORY_ID_USER[0])
				vw[2] = "user";
			else if (type == DIRECTORY_ID_GROUP[0])
				vw[2] = "group";
			else
				vw[2] = "*";

			/*
			 * Try samAccountName.
			 * Note that here we rely on checking the returned
			 * distinguishedName to make sure that we found an
			 * entry from the right domain, because there's no
			 * attribute we can straightforwardly filter for to
			 * match domain.
			 *
			 * Eventually we should perhaps also try
			 * userPrincipalName.
			 */
			ldap_build_filter(filter, sizeof (filter),
			    "(&(samAccountName=%v1)(objectClass=%v3))",
			    NULL, NULL, NULL, NULL, vw);

			de = directory_provider_ad_lookup(&del[i], attrs2,
			    attrs->idmap_utf8str_list_len, vw[1], filter);
			if (de != NULL) {
				directory_entry_set_error(&del[i], de);
				de = NULL;
			}
		}
	}

	de = NULL;

	goto out;

nomem:
	de = directory_error("ENOMEM.AD",
	    "Out of memory during AD lookup", NULL);
out:
	free(attrs2);
	return (de);
}

/*
 * Note that attrs is NULL terminated, and that nattrs is the number
 * of attributes requested by the user... which might be fewer than are
 * in attrs because of attributes that we need for our own processing.
 */
static
directory_error_t
directory_provider_ad_lookup(
    directory_entry_rpc *pent,
    const char * const * attrs,
    int nattrs,
    const char *domain,
    const char *filter)
{
	adutils_ad_t *ad;
	adutils_rc batchrc;
	struct cbinfo cbinfo;
	adutils_query_state_t *qs;
	int rc;

	/*
	 * NEEDSWORK:  Should eventually handle other forests.
	 * NEEDSWORK:  Should eventually handle non-GC attributes.
	 */
	ad = _idmapdstate.gcs[0];

	/* Stash away information for the callback function. */
	cbinfo.attrs = attrs;
	cbinfo.nattrs = nattrs;
	cbinfo.entry = pent;
	cbinfo.domain = domain;

	rc = adutils_lookup_batch_start(ad, 1, directory_provider_ad_cb,
	    &cbinfo, &qs);
	if (rc != ADUTILS_SUCCESS) {
		return (directory_provider_ad_utils_error(
		    "adutils_lookup_batch_start", rc));
	}

	rc = adutils_lookup_batch_add(qs, filter, attrs, domain,
	    NULL, &batchrc);
	if (rc != ADUTILS_SUCCESS) {
		adutils_lookup_batch_release(&qs);
		return (directory_provider_ad_utils_error(
		    "adutils_lookup_batch_add", rc));
	}

	rc = adutils_lookup_batch_end(&qs);
	if (rc != ADUTILS_SUCCESS) {
		return (directory_provider_ad_utils_error(
		    "adutils_lookup_batch_end", rc));
	}

	if (batchrc != ADUTILS_SUCCESS) {
		/*
		 * NEEDSWORK:  We're consistently getting -9997 here.
		 * What does it mean?
		 */
		return (NULL);
	}

	return (NULL);
}

/*
 * Callback from the LDAP functions when they get responses.
 * We don't really need (nor want) asynchronous handling, but it's
 * what libadutils gives us.
 */
static
void
directory_provider_ad_cb(
    LDAP *ld,
    LDAPMessage **ldapres,
    int rc,
    int qid,
    void *argp)
{
	NOTE(ARGUNUSED(rc, qid))
	struct cbinfo *cbinfo = (struct cbinfo *)argp;
	LDAPMessage *msg = *ldapres;

	for (msg = ldap_first_entry(ld, msg);
	    msg != NULL;
	    msg = ldap_next_entry(ld, msg)) {
		directory_provider_ad_cb1(ld, msg, cbinfo);
	}
}

/*
 * Process a single entry returned by an LDAP callback.
 * Note that this performs a function roughly equivalent to the
 * directory*Populate() functions in the other providers.
 * Given an LDAP response, populate the directory entry for return to
 * the caller.  This one differs primarily in that we're working directly
 * with LDAP, so we don't have to do any attribute translation.
 */
static
void
directory_provider_ad_cb1(
    LDAP *ld,
    LDAPMessage *msg,
    struct cbinfo *cbinfo)
{
	int nattrs = cbinfo->nattrs;
	const char * const *attrs = cbinfo->attrs;
	directory_entry_rpc *pent = cbinfo->entry;

	int i;
	directory_values_rpc *llvals;
	directory_error_t de;
	char *domain = NULL;

	/*
	 * We don't have a way to filter for entries from the right domain
	 * in the LDAP query, so we check for it here.  Searches based on
	 * samAccountName might yield results from the wrong domain.
	 */
	de = get_domain(ld, msg, &domain);
	if (de != NULL)
		goto err;

	if (cbinfo->domain != NULL && !domain_eq(cbinfo->domain, domain))
		goto out;

	/*
	 * If we've already found a match, error.
	 */
	if (pent->status != DIRECTORY_NOT_FOUND) {
		de = directory_error("Duplicate.AD",
		    "Multiple matching entries found", NULL);
		goto err;
	}

	llvals = calloc(nattrs, sizeof (directory_values_rpc));
	if (llvals == NULL)
		goto nomem;

	pent->directory_entry_rpc_u.attrs.attrs_val = llvals;
	pent->directory_entry_rpc_u.attrs.attrs_len = nattrs;
	pent->status = DIRECTORY_FOUND;

	for (i = 0; i < nattrs; i++) {
		struct berval **bv;
		const char *a = attrs[i];
		directory_values_rpc *val = &llvals[i];

		bv = ldap_get_values_len(ld, msg, a);
#if	defined(DUMP_VALUES)
		dump_bv_list(attrs[i], bv);
#endif
		if (bv != NULL) {
			de = bv_list_dav(val, bv);
			ldap_value_free_len(bv);
			if (de != NULL)
				goto err;
		} else if (uu_strcaseeq(a, "x-sun-canonicalName")) {
			bv = ldap_get_values_len(ld, msg, "sAMAccountName");
			if (bv != NULL) {
				int n = ldap_count_values_len(bv);
				if (n > 0) {
					char *tmp;
					(void) asprintf(&tmp, "%.*s@%s",
					    bv[0]->bv_len, bv[0]->bv_val,
					    domain);
					if (tmp == NULL)
						goto nomem;
					const char *ctmp = tmp;
					de = str_list_dav(val, &ctmp, 1);
					free(tmp);
					if (de != NULL)
						goto err;
				}
			}
		} else if (uu_strcaseeq(a, "x-sun-provider")) {
			const char *provider = "LDAP-AD";
			de = str_list_dav(val, &provider, 1);
		}
	}

	goto out;

nomem:
	de = directory_error("ENOMEM.users",
	    "No memory allocating return value for user lookup", NULL);

err:
	directory_entry_set_error(pent, de);
	de = NULL;

out:
	free(domain);
}

/*
 * Given a struct berval, populate a directory attribute value (which is a
 * list of values).
 * Note that here we populate the DAV with the exact bytes that LDAP returns.
 * Back over in the client it appends a \0 so that strings are null
 * terminated.
 */
static
directory_error_t
bv_list_dav(directory_values_rpc *lvals, struct berval **bv)
{
	directory_value_rpc *dav;
	int n;
	int i;

	n = ldap_count_values_len(bv);

	dav = calloc(n, sizeof (directory_value_rpc));
	if (dav == NULL)
		goto nomem;

	lvals->directory_values_rpc_u.values.values_val = dav;
	lvals->directory_values_rpc_u.values.values_len = n;
	lvals->found = TRUE;

	for (i = 0; i < n; i++) {
		dav[i].directory_value_rpc_val =
		    uu_memdup(bv[i]->bv_val, bv[i]->bv_len);
		if (dav[i].directory_value_rpc_val == NULL)
			goto nomem;
		dav[i].directory_value_rpc_len = bv[i]->bv_len;
	}

	return (NULL);

nomem:
	return (directory_error("ENOMEM.bv_list_dav",
	    "Insufficient memory copying values"));
}

#if	defined(DUMP_VALUES)
static
void
dump_bv_list(const char *attr, struct berval **bv)
{
	int i;

	if (bv == NULL) {
		(void) fprintf(stderr, "%s:  (empty)\n", attr);
		return;
	}
	for (i = 0; bv[i] != NULL; i++) {
		(void) fprintf(stderr, "%s[%d] =\n", attr, i);
		dump(stderr, "    ", bv[i]->bv_val, bv[i]->bv_len);
	}
}
#endif	/* DUMP_VALUES */

/*
 * Return the domain associated with the specified entry.
 */
static
directory_error_t
get_domain(
    LDAP *ld,
    LDAPMessage *msg,
    char **domain)
{
	*domain = NULL;

	char *dn = ldap_get_dn(ld, msg);
	if (dn == NULL) {
		char buf[100];	/* big enough for any int */
		char *m;
		char *s;
		int err = ldap_get_lderrno(ld, &m, &s);
		(void) snprintf(buf, sizeof (buf), "%d", err);

		return directory_error("AD.get_domain.ldap_get_dn",
		    "ldap_get_dn: %1 (%2)\n"
		    "matched: %3\n"
		    "error:   %4",
		    ldap_err2string(err), buf,
		    m == NULL ? "(null)" : m,
		    s == NULL ? "(null)" : s,
		    NULL);
	}

	*domain = adutils_dn2dns(dn);
	if (*domain == NULL) {
		directory_error_t de;

		de = directory_error("Unknown.get_domain.adutils_dn2dns",
		    "get_domain:  Unexpected error from adutils_dn2dns(%1)",
		    dn, NULL);
		free(dn);
		return (de);
	}
	free(dn);

	return (NULL);
}

/*
 * Given an error report from libadutils, generate a directory_error_t.
 */
static
directory_error_t
directory_provider_ad_utils_error(char *func, int rc)
{
	char rcstr[100];	/* plenty for any int */
	char code[100];		/* plenty for any int */
	(void) snprintf(rcstr, sizeof (rcstr), "%d", rc);
	(void) snprintf(code, sizeof (code), "ADUTILS.%d", rc);

	return (directory_error(code,
	    "Error %2 from adutils function %1", func, rcstr, NULL));
}

struct directory_provider_static directory_provider_ad = {
	"AD",
	directory_provider_ad_get,
};
