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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Processes name2sid & sid2name batched lookups for a given user or
 * computer from an AD Directory server using GSSAPI authentication
 */

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <strings.h>
#include <lber.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <synch.h>
#include <atomic.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <time.h>
#include <sys/u8_textprep.h>
#include "libadutils.h"
#include "nldaputils.h"
#include "idmapd.h"

/* Attribute names and filter format strings */
#define	SAN		"sAMAccountName"
#define	OBJSID		"objectSid"
#define	OBJCLASS	"objectClass"
#define	UIDNUMBER	"uidNumber"
#define	GIDNUMBER	"gidNumber"
#define	UIDNUMBERFILTER	"(&(objectclass=user)(uidNumber=%u))"
#define	GIDNUMBERFILTER	"(&(objectclass=group)(gidNumber=%u))"
#define	SANFILTER	"(sAMAccountName=%s)"
#define	OBJSIDFILTER	"(|(objectSid=%s)(sIDHistory=%s))"

void	idmap_ldap_res_search_cb(LDAP *ld, LDAPMessage **res, int rc,
		int qid, void *argp);

/*
 * A place to put the results of a batched (async) query
 *
 * There is one of these for every query added to a batch object
 * (idmap_query_state, see below).
 */
typedef struct idmap_q {
	/*
	 * data used for validating search result entries for name->SID
	 * lookups
	 */
	char			*ecanonname;	/* expected canon name */
	char			*edomain;	/* expected domain name */
	idmap_id_type		esidtype;	/* expected SID type */
	/* results */
	char			**canonname;	/* actual canon name */
	char			**domain;	/* name of domain of object */
	char			**sid;		/* stringified SID */
	rid_t			*rid;		/* RID */
	idmap_id_type		*sid_type;	/* user or group SID? */
	char			**unixname;	/* unixname for name mapping */
	char			**dn;		/* DN of entry */
	char			**attr;		/* Attr for name mapping */
	char			**value;	/* value for name mapping */
	posix_id_t		*pid;		/* Posix ID found via IDMU */
	idmap_retcode		*rc;
	adutils_rc		ad_rc;
	adutils_result_t	*result;

	/*
	 * The LDAP search entry result is placed here to be processed
	 * when the search done result is received.
	 */
	LDAPMessage		*search_res;	/* The LDAP search result */
} idmap_q_t;

/* Batch context structure; typedef is in header file */
struct idmap_query_state {
	adutils_query_state_t	*qs;
	int			qsize;		/* Queue size */
	uint32_t		qcount;		/* Number of queued requests */
	const char		*ad_unixuser_attr;
	const char		*ad_unixgroup_attr;
	int			directory_based_mapping;	/* enum */
	char			*default_domain;
	idmap_q_t		queries[1];	/* array of query results */
};

static pthread_t	reaperid = 0;

/*
 * Keep connection management simple for now, extend or replace later
 * with updated libsldap code.
 */
#define	ADREAPERSLEEP	60

/*
 * Idle connection reaping side of connection management
 *
 * Every minute wake up and look for connections that have been idle for
 * five minutes or more and close them.
 */
/*ARGSUSED*/
static
void *
adreaper(void *arg __unused)
{
	timespec_t	ts;

	ts.tv_sec = ADREAPERSLEEP;
	ts.tv_nsec = 0;

	for (;;) {
		/*
		 * nanosleep(3C) is thread-safe (no SIGALRM) and more
		 * portable than usleep(3C)
		 */
		(void) nanosleep(&ts, NULL);
		adutils_reap_idle_connections();
	}
	return (NULL);
}

/*
 * Take ad_host_config_t information, create a ad_host_t,
 * populate it and add it to the list of hosts.
 */

int
idmap_add_ds(adutils_ad_t *ad, const char *host, int port)
{
	int	ret = -1;

	if (adutils_add_ds(ad, host, port) == ADUTILS_SUCCESS)
		ret = 0;

	/* Start reaper if it doesn't exist */
	if (ret == 0 && reaperid == 0)
		(void) pthread_create(&reaperid, NULL, adreaper, NULL);
	return (ret);
}

static
idmap_retcode
map_adrc2idmaprc(adutils_rc adrc)
{
	switch (adrc) {
	case ADUTILS_SUCCESS:
		return (IDMAP_SUCCESS);
	case ADUTILS_ERR_NOTFOUND:
		return (IDMAP_ERR_NOTFOUND);
	case ADUTILS_ERR_MEMORY:
		return (IDMAP_ERR_MEMORY);
	case ADUTILS_ERR_DOMAIN:
		return (IDMAP_ERR_DOMAIN);
	case ADUTILS_ERR_OTHER:
		return (IDMAP_ERR_OTHER);
	case ADUTILS_ERR_RETRIABLE_NET_ERR:
		return (IDMAP_ERR_RETRIABLE_NET_ERR);
	default:
		return (IDMAP_ERR_INTERNAL);
	}
	/* NOTREACHED */
}

idmap_retcode
idmap_lookup_batch_start(adutils_ad_t *ad, int nqueries,
    int directory_based_mapping, const char *default_domain,
    idmap_query_state_t **state)
{
	idmap_query_state_t	*new_state;
	adutils_rc		rc;

	*state = NULL;

	assert(ad != NULL);

	new_state = calloc(1, sizeof (idmap_query_state_t) +
	    (nqueries - 1) * sizeof (idmap_q_t));
	if (new_state == NULL)
		return (IDMAP_ERR_MEMORY);

	if ((rc = adutils_lookup_batch_start(ad, nqueries,
	    idmap_ldap_res_search_cb, new_state, &new_state->qs))
	    != ADUTILS_SUCCESS) {
		idmap_lookup_release_batch(&new_state);
		return (map_adrc2idmaprc(rc));
	}

	new_state->default_domain = strdup(default_domain);
	if (new_state->default_domain == NULL) {
		idmap_lookup_release_batch(&new_state);
		return (IDMAP_ERR_MEMORY);
	}

	new_state->directory_based_mapping = directory_based_mapping;
	new_state->qsize = nqueries;
	*state = new_state;
	return (IDMAP_SUCCESS);
}

/*
 * Set unixuser_attr and unixgroup_attr for AD-based name mapping
 */
void
idmap_lookup_batch_set_unixattr(idmap_query_state_t *state,
    const char *unixuser_attr, const char *unixgroup_attr)
{
	state->ad_unixuser_attr = unixuser_attr;
	state->ad_unixgroup_attr = unixgroup_attr;
}

/*
 * Take parsed attribute values from a search result entry and check if
 * it is the result that was desired and, if so, set the result fields
 * of the given idmap_q_t.
 *
 * Except for dn and attr, all strings are consumed, either by transferring
 * them over into the request results (where the caller will eventually free
 * them) or by freeing them here.  Note that this aligns with the "const"
 * declarations below.
 */
static
void
idmap_setqresults(
    idmap_q_t *q,
    char *san,
    const char *dn,
    const char *attr,
    char *value,
    char *sid,
    rid_t rid,
    int sid_type,
    char *unixname,
    posix_id_t pid)
{
	char *domain;
	int err1;

	assert(dn != NULL);

	if ((domain = adutils_dn2dns(dn)) == NULL)
		goto out;

	if (q->ecanonname != NULL && san != NULL) {
		/* Check that this is the canonname that we were looking for */
		if (u8_strcmp(q->ecanonname, san, 0,
		    U8_STRCMP_CI_LOWER, /* no normalization, for now */
		    U8_UNICODE_LATEST, &err1) != 0 || err1 != 0)
			goto out;
	}

	if (q->edomain != NULL) {
		/* Check that this is the domain that we were looking for */
		if (!domain_eq(q->edomain, domain))
			goto out;
	}

	/* Copy the DN and attr and value */
	if (q->dn != NULL)
		*q->dn = strdup(dn);

	if (q->attr != NULL && attr != NULL)
		*q->attr = strdup(attr);

	if (q->value != NULL && value != NULL) {
		*q->value = value;
		value = NULL;
	}

	/* Set results */
	if (q->sid) {
		*q->sid = sid;
		sid = NULL;
	}
	if (q->rid)
		*q->rid = rid;
	if (q->sid_type)
		*q->sid_type = sid_type;
	if (q->unixname) {
		*q->unixname = unixname;
		unixname = NULL;
	}
	if (q->domain != NULL) {
		*q->domain = domain;
		domain = NULL;
	}
	if (q->canonname != NULL) {
		/*
		 * The caller may be replacing the given winname by its
		 * canonical name and therefore free any old name before
		 * overwriting the field by the canonical name.
		 */
		free(*q->canonname);
		*q->canonname = san;
		san = NULL;
	}

	if (q->pid != NULL && pid != IDMAP_SENTINEL_PID) {
		*q->pid = pid;
	}

	q->ad_rc = ADUTILS_SUCCESS;

out:
	/* Free unused attribute values */
	free(san);
	free(sid);
	free(domain);
	free(unixname);
	free(value);
}

#define	BVAL_CASEEQ(bv, str) \
		(((*(bv))->bv_len == (sizeof (str) - 1)) && \
		    strncasecmp((*(bv))->bv_val, str, (*(bv))->bv_len) == 0)

/*
 * Extract the class of the result entry.  Returns 1 on success, 0 on
 * failure.
 */
static
int
idmap_bv_objclass2sidtype(BerValue **bvalues, int *sid_type)
{
	BerValue	**cbval;

	*sid_type = IDMAP_SID;
	if (bvalues == NULL)
		return (0);

	/*
	 * We consider Computer to be a subclass of User, so we can just
	 * ignore Computer entries and pay attention to the accompanying
	 * User entries.
	 */
	for (cbval = bvalues; *cbval != NULL; cbval++) {
		if (BVAL_CASEEQ(cbval, "group")) {
			*sid_type = IDMAP_GSID;
			break;
		} else if (BVAL_CASEEQ(cbval, "user")) {
			*sid_type = IDMAP_USID;
			break;
		}
		/*
		 * "else if (*sid_type = IDMAP_USID)" then this is a
		 * new sub-class of user -- what to do with it??
		 */
	}

	return (1);
}

/*
 * Handle a given search result entry
 */
static
void
idmap_extract_object(idmap_query_state_t *state, idmap_q_t *q,
    LDAPMessage *res, LDAP *ld)
{
	BerValue		**bvalues;
	const char		*attr = NULL;
	char			*value = NULL;
	char			*unix_name = NULL;
	char			*dn;
	char			*san = NULL;
	char			*sid = NULL;
	rid_t			rid = 0;
	int			sid_type;
	int			ok;
	posix_id_t		pid = IDMAP_SENTINEL_PID;

	assert(q->rc != NULL);
	assert(q->domain == NULL || *q->domain == NULL);

	if ((dn = ldap_get_dn(ld, res)) == NULL)
		return;

	bvalues = ldap_get_values_len(ld, res, OBJCLASS);
	if (bvalues == NULL) {
		/*
		 * Didn't find objectclass. Something's wrong with our
		 * AD data.
		 */
		idmapdlog(LOG_ERR, "%s has no %s", dn, OBJCLASS);
		goto out;
	}
	ok = idmap_bv_objclass2sidtype(bvalues, &sid_type);
	ldap_value_free_len(bvalues);
	if (!ok) {
		/*
		 * Didn't understand objectclass. Something's wrong with our
		 * AD data.
		 */
		idmapdlog(LOG_ERR, "%s has unexpected %s", dn, OBJCLASS);
		goto out;
	}

	if (state->directory_based_mapping == DIRECTORY_MAPPING_IDMU &&
	    q->pid != NULL) {
		if (sid_type == IDMAP_USID)
			attr = UIDNUMBER;
		else if (sid_type == IDMAP_GSID)
			attr = GIDNUMBER;
		if (attr != NULL) {
			bvalues = ldap_get_values_len(ld, res, attr);
			if (bvalues != NULL) {
				value = adutils_bv_str(bvalues[0]);
				if (!adutils_bv_uint(bvalues[0], &pid)) {
					idmapdlog(LOG_ERR,
					    "%s has Invalid %s value \"%s\"",
					    dn, attr, value);
				}
				ldap_value_free_len(bvalues);
			}
		}
	}

	if (state->directory_based_mapping == DIRECTORY_MAPPING_NAME &&
	    q->unixname != NULL) {
		/*
		 * If the caller has requested unixname then determine the
		 * AD attribute name that will have the unixname, and retrieve
		 * its value.
		 */
		idmap_id_type esidtype;
		/*
		 * Determine the target type.
		 *
		 * If the caller specified one, use that.  Otherwise, give the
		 * same type that as we found for the Windows user.
		 */
		esidtype = q->esidtype;
		if (esidtype == IDMAP_SID)
			esidtype = sid_type;

		if (esidtype == IDMAP_USID)
			attr = state->ad_unixuser_attr;
		else if (esidtype == IDMAP_GSID)
			attr = state->ad_unixgroup_attr;

		if (attr != NULL) {
			bvalues = ldap_get_values_len(ld, res, attr);
			if (bvalues != NULL) {
				unix_name = adutils_bv_str(bvalues[0]);
				ldap_value_free_len(bvalues);
				value = strdup(unix_name);
			}
		}
	}

	bvalues = ldap_get_values_len(ld, res, SAN);
	if (bvalues != NULL) {
		san = adutils_bv_str(bvalues[0]);
		ldap_value_free_len(bvalues);
	}

	if (q->sid != NULL) {
		bvalues = ldap_get_values_len(ld, res, OBJSID);
		if (bvalues != NULL) {
			sid = adutils_bv_objsid2sidstr(bvalues[0], &rid);
			ldap_value_free_len(bvalues);
		}
	}

	idmap_setqresults(q, san, dn,
	    attr, value,
	    sid, rid, sid_type,
	    unix_name, pid);

out:
	ldap_memfree(dn);
}

void
idmap_ldap_res_search_cb(LDAP *ld, LDAPMessage **res, int rc, int qid,
    void *argp)
{
	idmap_query_state_t	*state = (idmap_query_state_t *)argp;
	idmap_q_t		*q = &(state->queries[qid]);

	switch (rc) {
	case LDAP_RES_SEARCH_RESULT:
		if (q->search_res != NULL) {
			idmap_extract_object(state, q, q->search_res, ld);
			(void) ldap_msgfree(q->search_res);
			q->search_res = NULL;
		} else
			q->ad_rc = ADUTILS_ERR_NOTFOUND;
		break;
	case LDAP_RES_SEARCH_ENTRY:
		if (q->search_res == NULL) {
			q->search_res = *res;
			*res = NULL;
		}
		break;
	default:
		break;
	}
}

static
void
idmap_cleanup_batch(idmap_query_state_t *batch)
{
	int i;

	for (i = 0; i < batch->qcount; i++) {
		if (batch->queries[i].ecanonname != NULL)
			free(batch->queries[i].ecanonname);
		batch->queries[i].ecanonname = NULL;
		if (batch->queries[i].edomain != NULL)
			free(batch->queries[i].edomain);
		batch->queries[i].edomain = NULL;
	}
}

/*
 * This routine frees the idmap_query_state_t structure
 */
void
idmap_lookup_release_batch(idmap_query_state_t **state)
{
	if (state == NULL || *state == NULL)
		return;
	adutils_lookup_batch_release(&(*state)->qs);
	idmap_cleanup_batch(*state);
	free((*state)->default_domain);
	free(*state);
	*state = NULL;
}

idmap_retcode
idmap_lookup_batch_end(idmap_query_state_t **state)
{
	adutils_rc		ad_rc;
	int			i;
	idmap_query_state_t	*id_qs = *state;

	ad_rc = adutils_lookup_batch_end(&id_qs->qs);

	/*
	 * Map adutils rc to idmap_retcode in each
	 * query because consumers in dbutils.c
	 * expects idmap_retcode.
	 */
	for (i = 0; i < id_qs->qcount; i++) {
		*id_qs->queries[i].rc =
		    map_adrc2idmaprc(id_qs->queries[i].ad_rc);
	}
	idmap_lookup_release_batch(state);
	return (map_adrc2idmaprc(ad_rc));
}

/*
 * Send one prepared search, queue up msgid, process what results are
 * available
 */
static
idmap_retcode
idmap_batch_add1(idmap_query_state_t *state, const char *filter,
    char *ecanonname, char *edomain, idmap_id_type esidtype,
    char **dn, char **attr, char **value,
    char **canonname, char **dname,
    char **sid, rid_t *rid, idmap_id_type *sid_type, char **unixname,
    posix_id_t *pid,
    idmap_retcode *rc)
{
	adutils_rc	ad_rc;
	int		qid, i;
	idmap_q_t	*q;
	char	*attrs[20];	/* Plenty */

	qid = atomic_inc_32_nv(&state->qcount) - 1;
	q = &(state->queries[qid]);

	assert(qid < state->qsize);

	/*
	 * Remember the expected canonname, domainname and unix type
	 * so we can check the results * against it
	 */
	q->ecanonname = ecanonname;
	q->edomain = edomain;
	q->esidtype = esidtype;

	/* Remember where to put the results */
	q->canonname = canonname;
	q->sid = sid;
	q->domain = dname;
	q->rid = rid;
	q->sid_type = sid_type;
	q->rc = rc;
	q->unixname = unixname;
	q->dn = dn;
	q->attr = attr;
	q->value = value;
	q->pid = pid;

	/* Add attributes that are not always needed */
	i = 0;
	attrs[i++] = SAN;
	attrs[i++] = OBJSID;
	attrs[i++] = OBJCLASS;

	if (unixname != NULL) {
		/* Add unixuser/unixgroup attribute names to the attrs list */
		if (esidtype != IDMAP_GSID &&
		    state->ad_unixuser_attr != NULL)
			attrs[i++] = (char *)state->ad_unixuser_attr;
		if (esidtype != IDMAP_USID &&
		    state->ad_unixgroup_attr != NULL)
			attrs[i++] = (char *)state->ad_unixgroup_attr;
	}

	if (pid != NULL) {
		if (esidtype != IDMAP_GSID)
			attrs[i++] = UIDNUMBER;
		if (esidtype != IDMAP_USID)
			attrs[i++] = GIDNUMBER;
	}

	attrs[i] = NULL;

	/*
	 * Provide sane defaults for the results in case we never hear
	 * back from the DS before closing the connection.
	 *
	 * In particular we default the result to indicate a retriable
	 * error.  The first complete matching result entry will cause
	 * this to be set to IDMAP_SUCCESS, and the end of the results
	 * for this search will cause this to indicate "not found" if no
	 * result entries arrived or no complete ones matched the lookup
	 * we were doing.
	 */
	*rc = IDMAP_ERR_RETRIABLE_NET_ERR;
	if (sid_type != NULL)
		*sid_type = IDMAP_SID;
	if (sid != NULL)
		*sid = NULL;
	if (dname != NULL)
		*dname = NULL;
	if (rid != NULL)
		*rid = 0;
	if (dn != NULL)
		*dn = NULL;
	if (attr != NULL)
		*attr = NULL;
	if (value != NULL)
		*value = NULL;

	/*
	 * Don't set *canonname to NULL because it may be pointing to the
	 * given winname. Later on if we get a canonical name from AD the
	 * old name if any will be freed before assigning the new name.
	 */

	/*
	 * Invoke the mother of all APIs i.e. the adutils API
	 */
	ad_rc = adutils_lookup_batch_add(state->qs, filter,
	    (const char **)attrs,
	    edomain, &q->result, &q->ad_rc);
	return (map_adrc2idmaprc(ad_rc));
}

idmap_retcode
idmap_name2sid_batch_add1(idmap_query_state_t *state,
    const char *name, const char *dname, idmap_id_type esidtype,
    char **dn, char **attr, char **value,
    char **canonname, char **sid, rid_t *rid,
    idmap_id_type *sid_type, char **unixname,
    posix_id_t *pid, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	char		*filter, *s_name;
	char		*ecanonname, *edomain; /* expected canonname */

	/*
	 * Strategy: search the global catalog for user/group by
	 * sAMAccountName = user/groupname with "" as the base DN and by
	 * userPrincipalName = user/groupname@domain.  The result
	 * entries will be checked to conform to the name and domain
	 * name given here.  The DN, sAMAccountName, userPrincipalName,
	 * objectSid and objectClass of the result entries are all we
	 * need to figure out which entries match the lookup, the SID of
	 * the user/group and whether it is a user or a group.
	 */

	if ((ecanonname = strdup(name)) == NULL)
		return (IDMAP_ERR_MEMORY);

	if (dname == NULL || *dname == '\0') {
		/* 'name' not qualified and dname not given */
		dname = state->default_domain;
		edomain = strdup(dname);
		if (edomain == NULL) {
			free(ecanonname);
			return (IDMAP_ERR_MEMORY);
		}
	} else {
		if ((edomain = strdup(dname)) == NULL) {
			free(ecanonname);
			return (IDMAP_ERR_MEMORY);
		}
	}

	if (!adutils_lookup_check_domain(state->qs, dname)) {
		free(ecanonname);
		free(edomain);
		return (IDMAP_ERR_DOMAIN_NOTFOUND);
	}

	s_name = sanitize_for_ldap_filter(name);
	if (s_name == NULL) {
		free(ecanonname);
		free(edomain);
		return (IDMAP_ERR_MEMORY);
	}

	/* Assemble filter */
	(void) asprintf(&filter, SANFILTER, s_name);
	if (s_name != name)
		free(s_name);
	if (filter == NULL) {
		free(ecanonname);
		free(edomain);
		return (IDMAP_ERR_MEMORY);
	}

	retcode = idmap_batch_add1(state, filter, ecanonname, edomain,
	    esidtype, dn, attr, value, canonname, NULL, sid, rid, sid_type,
	    unixname, pid, rc);

	free(filter);

	return (retcode);
}

idmap_retcode
idmap_sid2name_batch_add1(idmap_query_state_t *state,
    const char *sid, const rid_t *rid, idmap_id_type esidtype,
    char **dn, char **attr, char **value,
    char **name, char **dname, idmap_id_type *sid_type,
    char **unixname, posix_id_t *pid, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	int		ret;
	char		*filter;
	char		cbinsid[ADUTILS_MAXHEXBINSID + 1];

	/*
	 * Strategy: search [the global catalog] for user/group by
	 * objectSid = SID with empty base DN.  The DN, sAMAccountName
	 * and objectClass of the result are all we need to figure out
	 * the name of the SID and whether it is a user, a group or a
	 * computer.
	 */

	if (!adutils_lookup_check_sid_prefix(state->qs, sid))
		return (IDMAP_ERR_DOMAIN_NOTFOUND);

	ret = adutils_txtsid2hexbinsid(sid, rid, &cbinsid[0], sizeof (cbinsid));
	if (ret != 0)
		return (IDMAP_ERR_SID);

	/* Assemble filter */
	(void) asprintf(&filter, OBJSIDFILTER, cbinsid, cbinsid);
	if (filter == NULL)
		return (IDMAP_ERR_MEMORY);

	retcode = idmap_batch_add1(state, filter, NULL, NULL, esidtype,
	    dn, attr, value, name, dname, NULL, NULL, sid_type, unixname,
	    pid, rc);

	free(filter);

	return (retcode);
}

idmap_retcode
idmap_unixname2sid_batch_add1(idmap_query_state_t *state,
    const char *unixname, int is_user, int is_wuser,
    char **dn, char **attr, char **value,
    char **sid, rid_t *rid, char **name,
    char **dname, idmap_id_type *sid_type, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	char		*filter, *s_unixname;
	const char	*attrname;

	/* Get unixuser or unixgroup AD attribute name */
	attrname = (is_user) ?
	    state->ad_unixuser_attr : state->ad_unixgroup_attr;
	if (attrname == NULL)
		return (IDMAP_ERR_NOTFOUND);

	s_unixname = sanitize_for_ldap_filter(unixname);
	if (s_unixname == NULL)
		return (IDMAP_ERR_MEMORY);

	/*  Assemble filter */
	(void) asprintf(&filter, "(&(objectclass=%s)(%s=%s))",
	    is_wuser ? "user" : "group", attrname, s_unixname);
	if (s_unixname != unixname)
		free(s_unixname);
	if (filter == NULL) {
		return (IDMAP_ERR_MEMORY);
	}

	retcode = idmap_batch_add1(state, filter, NULL, NULL,
	    IDMAP_POSIXID, dn, NULL, NULL, name, dname, sid, rid, sid_type,
	    NULL, NULL, rc);

	if (retcode == IDMAP_SUCCESS && attr != NULL) {
		if ((*attr = strdup(attrname)) == NULL)
			retcode = IDMAP_ERR_MEMORY;
	}

	if (retcode == IDMAP_SUCCESS && value != NULL) {
		if ((*value = strdup(unixname)) == NULL)
			retcode = IDMAP_ERR_MEMORY;
	}

	free(filter);

	return (retcode);
}

idmap_retcode
idmap_pid2sid_batch_add1(idmap_query_state_t *state,
    posix_id_t pid, int is_user,
    char **dn, char **attr, char **value,
    char **sid, rid_t *rid, char **name,
    char **dname, idmap_id_type *sid_type, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	char		*filter;
	const char	*attrname;

	/*  Assemble filter */
	if (is_user) {
		(void) asprintf(&filter, UIDNUMBERFILTER, pid);
		attrname = UIDNUMBER;
	} else {
		(void) asprintf(&filter, GIDNUMBERFILTER, pid);
		attrname = GIDNUMBER;
	}
	if (filter == NULL)
		return (IDMAP_ERR_MEMORY);

	retcode = idmap_batch_add1(state, filter, NULL, NULL,
	    IDMAP_POSIXID, dn, NULL, NULL, name, dname, sid, rid, sid_type,
	    NULL, NULL, rc);

	if (retcode == IDMAP_SUCCESS && attr != NULL) {
		if ((*attr = strdup(attrname)) == NULL)
			retcode = IDMAP_ERR_MEMORY;
	}

	if (retcode == IDMAP_SUCCESS && value != NULL) {
		(void) asprintf(value, "%u", pid);
		if (*value == NULL)
			retcode = IDMAP_ERR_MEMORY;
	}

	free(filter);

	return (retcode);
}
