/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Target Lists
 * ============
 * All UA functions use target lists to select and manage their
 * network targets. There are two types of network targets: unicast (uc)
 * and multicast (mc) -- multicast will also work for broadcast. This
 * module organizes unicast targets into an efficient ordering. The
 * targeting structure can be though of as a 2-dimensional matrix, with
 * the following axes:
 *
 * unicast	failovers --->
 * targets
 *    |
 *    |
 *   \ /
 *
 * Callers walk down the unicast targets, unicasting to each. If any
 * unicast target fails, callers then walk to the right, through failover
 * targets until they either find one that works, or there are no more
 * failover targets.
 *
 * The targeting heuristic orders the unicast targets so that those
 * DAs which support the greatest number of requested scopes are called
 * first, thus minimizing the number of unicasts which need to be done.
 * Within groups of DAs supporting the same scope coverage, the DAs are
 * sorted according to network proximity relative to the local host:
 * DAs on the local host come first, then those on a same subnet, then
 * all other (remote) DAs.
 *
 * A given DA is called no more than once, and failed DAs are skipped
 * after they have been marked 'failed'.
 *
 * All access to a target list is done through the following functions
 * and types:
 * There are two opaque types:
 * slp_target_list_t:	A handle to a target list
 * slp_target_t:	A handle to an individual target. slp_get_target_sin
 *			will extract an inet address for this target.
 *
 * There are the following accessor functions:
 * slp_new_target_list: creates a new target list for the given scopes,
 *			and populates with all known DAs for these scopes.
 * slp_get_uc_scopes:	returns a list of all scopes for which there are
 *			DAs (and which can thus be used for unicasts)
 * slp_get_mc_scopes:	returns a list of all scopes for which there are
 *			no DAs (and which must thus be used for multicasts).
 * slp_next_uc_target:	Returns a slp_target_t handle for the next unicast
 *			target, or NULL for none.
 * slp_next_failover:	Returns the next failover DA for a given target, or
 *			NULL for none.
 * slp_get_target_sin:	extracts a sockaddr_in for a given slp_target_t;
 * slp_mark_target_used: callers should mark a slp_target_t used after
 *			successfully communicating with that target.
 * slp_mark_target_failed: callers should mark a slp_target_t failed after
 *			trying and failing to communicate with a target.
 * slp_destroy_target_list: destroys and frees a target list and all its
 *			associated resources.
 * slp_fabricate_target: Creates a slp_target_t from a given sockaddr_in.
 *			This is useful for situations such as when a
 *			multicast routine needs to hand off to a TCP
 *			routine (due to overflow), and there is no target
 *			list available. Fabricated targets should be free'd
 *			with slp_free_target; the input sin will duplicated
 *			in the target, so the caller can free it after
 *			calling slp_fabricate_target.
 * slp_free_target:	Frees an slp_target_t created by slp_fabricate_target.
 *			This should not be used to free any other target.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <slp-internal.h>
#include <slp_net_utils.h>

typedef enum {
	SLP_REMOTE_PROX	= 0,	/* remote to local host */
	SLP_SUBNET_PROX	= 1,	/* on same subnet as local host */
	SLP_LOCAL_PROX	= 2	/* on local host */
} slp_net_prox;

struct da_node {
	struct sockaddr_in sin;
	char *scopes;
	SLPBoolean used, failed;
	int coverage;
	slp_net_prox proximity;
	struct da_node *next, *prev;
};

struct scope_targets {
	struct da_node *da;
	struct scope_targets *next;
};

struct target_list {
	struct scope_targets **scopes;
	struct scope_targets **state;
	char *uc_scopes;
	char *mc_scopes;
	char *all_scopes;
	struct da_node *DAs;
};

static void add2scopes_list(struct da_node *, struct target_list *);
static void add_da_entry(struct da_node **, struct sockaddr_in *,
				char *, slp_net_prox, int);
static SLPSrvURLCallback collect_DAs;
static void format_query(char *, const char *);

SLPError slp_new_target_list(slp_handle_impl_t *hp, const char *scopes,
				slp_target_list_t **handle) {
	struct target_list *tl;
	int scope_cnt;
	char *p;
	struct da_node *te;
	char *query, *reply;
	SLPError err;
	void *collator = NULL;

	/* count the number of scopes in the list */
	scope_cnt = 0;
	for (p = (char *)scopes; p; p++) {
		p = slp_utf_strchr(p, ',');
		scope_cnt++;
		if (!p)
			break;
	}

	/* create a new target list */
	if (!(tl = calloc(1, sizeof (*tl)))) {
		slp_err(LOG_CRIT, 0, "slp_new_target_list", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	tl->DAs = NULL;

	if (!(tl->scopes = calloc(scope_cnt + 1, sizeof (*(tl->scopes))))) {
		slp_err(LOG_CRIT, 0, "slp_new_target_list", "out of memory");
		free(tl);
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	tl->uc_scopes = NULL;
	tl->state = tl->scopes;
	if (!(tl->all_scopes = strdup(scopes))) {
		slp_err(LOG_CRIT, 0, "slp_new_target_list", "out of memory");
		free(tl->scopes); free(tl);
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	/* As scopes are added to uc list, they are removed from the mc list */
	if (!(tl->mc_scopes = strdup(scopes))) {
		slp_err(LOG_CRIT, 0, "slp_new_target_list", "out of memory");
		free(tl->scopes); free(tl->all_scopes); free(tl);
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	if (hp->force_multicast) {
		/* all scopes remain multicast scopes; useful for SAAdverts */
		*handle = tl;
		return (SLP_OK);
	}

	/* DAs from active and passive discovery */
	if (!(query = malloc(strlen(scopes) -
				(scope_cnt - 1) +	/* exclude commas */
				strlen(SLP_SUN_VERSION_TAG) +
				strlen("(&(=2)(|))") + 1 +
				(scope_cnt *
					(strlen(SLP_SUN_SCOPES_TAG) +
					strlen("(=)")))))) {	/* (scopes=) */
		slp_err(LOG_CRIT, 0, "slp_new_target_list", "out of memory");
		free(tl->scopes);
		free(tl->all_scopes);
		free(tl->mc_scopes);
		free(tl);
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	format_query(query, scopes);

	if ((err = slp_find_das(query, &reply)) != SLP_OK &&
	    err != SLP_NETWORK_ERROR) {
		free(tl->scopes);
		free(tl->all_scopes);
		free(tl->mc_scopes);
		free(tl);
		free(query);
		return (err);
	}
	free(query);

	/* Unpack the reply */
	if (reply) {
		int numResults = 0;	/* placeholder; not actually used */
		/* tag call as internal */
		hp->internal_call = SLP_TRUE;

		(void) slp_unpackSrvReply(hp, reply, collect_DAs,
					tl, &collator, &numResults);
		free(reply);
		/* invoke last call */
		(void) slp_unpackSrvReply(hp, NULL, collect_DAs,
					tl, &collator, &numResults);

		/* revert internal call tag */
		hp->internal_call = SLP_FALSE;
	}

	/*
	 * tl->DAs now points to a list of DAs sorted by the number of
	 * relevant scopes they serve. Using this ordering, populate the
	 * scope array lists.
	 */
	for (te = tl->DAs; te; te = te->next)
		add2scopes_list(te, tl);

	*handle = tl;
	return (SLP_OK);
}

const char *slp_get_uc_scopes(slp_target_list_t *h) {
	struct target_list *tl = (struct target_list *)h;
	return (tl->uc_scopes);
}

const char *slp_get_mc_scopes(slp_target_list_t *h) {
	struct target_list *tl = (struct target_list *)h;
	return (tl->mc_scopes);
}

slp_target_t *slp_next_uc_target(slp_target_list_t *h) {
	struct scope_targets *p;
	struct target_list *tl = (struct target_list *)h;

	if (!(*tl->state))
		return (NULL);
	/* find the next unused target */
	for (; *tl->state; tl->state++) {
		if (!(*tl->state)->da->used && !(*tl->state)->da->failed)
			return (*tl->state++);
		if ((*tl->state)->da->failed) {
			/* get next failover */
			if (p = slp_next_failover(*tl->state)) {
				tl->state++;
				return (p);
			}
			/* else  nothing more we can do */
		}
	}
	return (NULL);
}

slp_target_t *slp_next_failover(slp_target_t *h) {
	struct scope_targets *p = (struct scope_targets *)h;
	for (p = p->next; p; p = p->next) {
		if (p->da->used)
			return (NULL);	/* already did this scope */
		if (!p->da->used && !p->da->failed)
			return (p);
	}
	return (NULL);
}

void *slp_get_target_sin(slp_target_t *h) {
	struct scope_targets *p = (struct scope_targets *)h;
	return (void *)(p ? &(p->da->sin) : NULL);
}

void slp_mark_target_used(slp_target_t *h) {
	struct scope_targets *p = (struct scope_targets *)h;
	p->da->used = SLP_TRUE;
}

void slp_mark_target_failed(slp_target_t *h) {
	struct scope_targets *p = (struct scope_targets *)h;
	p->da->failed = SLP_TRUE;
}

slp_target_t *slp_fabricate_target(void *s) {
	struct da_node *dn;
	struct scope_targets *st;
	struct sockaddr_in *sin = (struct sockaddr_in *)s;

	if (!(st = malloc(sizeof (*st)))) {
		slp_err(LOG_CRIT, 0, "slp_fabricate_target", "out of memory");
		return (NULL);
	}
	if (!(dn = malloc(sizeof (*dn)))) {
		free(st);
		slp_err(LOG_CRIT, 0, "slp_fabricate_target", "out of memory");
		return (NULL);
	}
	(void) memcpy(&(dn->sin), sin, sizeof (dn->sin));
	dn->used = dn->failed = SLP_FALSE;
	dn->coverage = 0;
	dn->proximity = SLP_REMOTE_PROX;
	dn->next = dn->prev = NULL;

	st->da = dn;
	st->next = NULL;

	return (st);
}

void slp_free_target(slp_target_t *target) {
	struct scope_targets *t = (struct scope_targets *)target;
	if (!t)
		return;
	free(t->da);
	free(t);
}

void slp_destroy_target_list(slp_target_list_t *h) {
	struct da_node *das, *dap;
	int i;
	struct target_list *tl = (struct target_list *)h;

	/* free da node list */
	for (das = tl->DAs; das; das = dap) {
		dap = das->next;
		free(das->scopes);
		free(das);
	}

	/* free scope target linked lists */
	for (i = 0; tl->scopes[i]; i++) {
		struct scope_targets *sts, *stp;
		for (sts = tl->scopes[i]; sts; sts = stp) {
			stp = sts->next;
			free(sts);
		}
	}

	/* free scope array */
	free(tl->scopes);

	/* free any char * lists in use */
	if (tl->uc_scopes)
		free(tl->uc_scopes);
	if (tl->mc_scopes)
		free(tl->mc_scopes);
	free(tl->all_scopes);

	/* free the target list struct */
	free(tl);
}

static void add2scopes_list(struct da_node *te, struct target_list *tl) {
	struct scope_targets **scopes = tl->scopes;
	char *p, *s;
	int i;

	/*
	 * for each scope in tl->uc_scopes:
	 * add this DA if it serves the scope.
	 */
	i = 0;
	for (s = tl->uc_scopes; s; s = p) {
		p = slp_utf_strchr(s, ',');
		if (p)
			*p = 0;
		if (slp_onlist(s, te->scopes)) {
			struct scope_targets *st, *stp;
			/* add this DA node to this scope's target list */
			if (!(st = malloc(sizeof (*st)))) {
				slp_err(LOG_CRIT, 0, "add2scopes_list",
					"out of memory");
				return;
			}
			st->da = te;
			st->next = NULL;
			/* find the end of the target list */
			for (stp = scopes[i]; stp && stp->next; ) {
				stp = stp->next;
			}
			if (stp)
				stp->next = st;
			else
				scopes[i] = st;
		}
		if (p)
			*p++ = ',';
		i++;
	}
}

static void add_da_entry(struct da_node **tel, struct sockaddr_in *sin,
				char *scopes, slp_net_prox proximity, int c) {
	struct da_node *te, *p;

	if (!(te = malloc(sizeof (*te)))) {
		slp_err(LOG_CRIT, 0, "add_da_entry", "out of memory");
		return;
	}
	te->scopes = scopes;
	te->coverage = c;
	te->proximity = proximity;
	(void) memcpy(&(te->sin), sin, sizeof (te->sin));
	te->used = SLP_FALSE;
	te->failed = SLP_FALSE;
	te->prev = NULL;
	te->next = NULL;

	/* find its place in the list */
	if (!(*tel)) {
		*tel = te;
		return;
	}
	for (p = *tel; p; p = p->next)
		if (c >= p->coverage) {
			/* found a coverage grouping; now sort by proximity */
			for (; p && proximity < p->proximity; )
				p = p->next;

			if (!p) {
				break;
			}

			/* add it here */
			te->next = p;
			te->prev = p->prev;
			if (p->prev)
				p->prev->next = te;
			else
				/* we're at the head */
				(*tel) = te;
			p->prev = te;
			return;
		}

	/* didn't find a place in the list, so add it at the end */
	for (p = *tel; p->next; )
		p = p->next;

	p->next = te;
	te->prev = p;
}

/*ARGSUSED*/
static SLPBoolean collect_DAs(SLPHandle h, const char *u,
				unsigned short lifetime,
				SLPError errCode, void *cookie) {
	SLPSrvURL *surl = NULL;
	char *s, *p, *sscopes, *sscopes_end, *url;
	int coverage, proximity;
	struct sockaddr_in sin[1];
	struct target_list *tl = (struct target_list *)cookie;

	if (errCode != SLP_OK)
		return (SLP_TRUE);

	/* dup url so as not to corrupt da cache */
	if (!(url = strdup(u))) {
		slp_err(LOG_CRIT, 0, "collect_DAs", "out of memory");
		return (SLP_FALSE);
	}

	/* parse url into a SLPSrvURL struct */
	if (SLPParseSrvURL(url, &surl) != SLP_OK) {
		return (SLP_TRUE);	/* bad URL; skip it */
	}

	/* determine proximity */
	if (slp_surl2sin(surl, sin) != SLP_OK) {
		goto cleanup;
	}
	if (slp_on_localhost(h, sin->sin_addr)) {
		proximity = SLP_LOCAL_PROX;
	} else if (slp_on_subnet(h, sin->sin_addr)) {
		proximity = SLP_SUBNET_PROX;
	} else {
		proximity = SLP_REMOTE_PROX;
	}

	/*
	 * sort the DAs into the entry list, ranked by the number of
	 * relevant scopes they serve (coverage).
	 */
	coverage = 0;
	if (!(sscopes = slp_utf_strchr(surl->s_pcSrvPart, '='))) {
		/* URL part should be of the form 'scopes=...' */
		goto cleanup;
	}
	sscopes++;

	/* cut off host scope at end */
	if (sscopes_end = slp_utf_strchr(sscopes, '=')) {
		/* skip the =[hostname] at the end */
		*sscopes_end = 0;
	}

	/* copy out the scopes part, since url will be freed after this call */
	if (!(sscopes = strdup(sscopes))) {
		slp_err(LOG_CRIT, 0, "collect_DAs", "out of memory");
		free(surl);
		return (SLP_FALSE);
	}

	for (s = tl->all_scopes; s; s = p) {
		p = slp_utf_strchr(s, ',');
		if (p)
			*p = 0;
		if (slp_onlist(s, sscopes)) {
			/* add to uc list; remove from mc list */
			slp_add2list(s, &(tl->uc_scopes), SLP_TRUE);
			slp_list_subtract(s, &(tl->mc_scopes));
			coverage++;
		}
		if (p)
			*p++ = ',';
	}
	if (coverage)
		add_da_entry(&(tl->DAs), sin, sscopes, proximity, coverage);

cleanup:
	free(url);
	if (surl) free(surl);

	return (SLP_TRUE);
}

/*
 * Takes a scopes list of the form 's1,s2,s3,...' and formats it into
 * an LDAP search filter of the form '(|(SCOPETAG=s1)(SCOPETAG=s2)...)'.
 * 'scopes' contains the scopes list; 'q' is a buffer allocated
 * by the caller into which the result will be placed.
 */
static void format_query(char *q, const char *scopes) {
	char *p, *s;
	int more_than_one = slp_utf_strchr(scopes, ',') ? 1 : 0;

	*q++ = '('; *q++ = '&';
	if (more_than_one) {
		*q++ = '('; *q++ = '|';
	}

	for (p = s = (char *)scopes; p; s = p) {
		*q++ = '(';
		(void) strcpy(q, SLP_SUN_SCOPES_TAG);
		q += strlen(SLP_SUN_SCOPES_TAG);
		*q++ = '=';

		p = slp_utf_strchr(s, ',');
		if (p) {
			(void) memcpy(q, s, p - s);
			q += (p - s);
			p++;
		} else {
			(void) strcpy(q, s);
			q += strlen(s);
		}
		*q++ = ')';
	}

	if (more_than_one) {
		*q++ = ')';
	}
	*q++ = '(';
	(void) strcpy(q, SLP_SUN_VERSION_TAG);
	q += strlen(SLP_SUN_VERSION_TAG);
	*q++ = '=';
	*q++ = '2';
	*q++ = ')';
	*q++ = ')';
	*q = 0;
}
