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

/*
 * Public utilities and convenience calls (from the API spec):
 *	SLPFindScopes (queries for all known scopes)
 *	SLPEscape / Unescape
 *	SLPFree
 *	SLPSet/GetProperty
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netdb.h>
#include <unistd.h>
#include <libintl.h>
#include <slp-internal.h>

struct scopes_tree {
	void *scopes;
	int len;
};

typedef SLPBoolean SLPScopeCallback(SLPHandle, const char *, SLPError, void *);

static SLPSrvURLCallback collate_scopes;
static void collect_scopes(void *, VISIT, int, void *);
static SLPBoolean unpackSAAdvert_scope(slp_handle_impl_t *, char *,
					SLPScopeCallback, void *,
					void **, int *);
static SLPError SAAdvert_for_scopes(SLPHandle, void **);
static SLPError slp_unescape(const char *, char **, SLPBoolean, const char);

/*
 * Finds scopes according the the user administrative model.
 */
SLPError SLPFindScopes(SLPHandle hSLP, char **ppcScopes) {
	SLPError err;
	char *reply, *unesc_reply;
	void *stree = NULL;
	void *collator = NULL;

	if (!hSLP || !ppcScopes) {
		return (SLP_PARAMETER_BAD);
	}

	/* first try administratively configured scopes */
	if ((err = slp_administrative_scopes(ppcScopes, SLP_FALSE))
	    != SLP_OK) {
		return (err);
	}

	if (*ppcScopes) {
	    /* got scopes */
	    return (SLP_OK);
	}

	/* DAs from active and passive discovery */
	if ((err = slp_find_das("", &reply)) != SLP_OK &&
	    err != SLP_NETWORK_ERROR)
		return (err);

	/* Unpack the reply */
	if (reply) {
		int numResults = 0;	/* placeholder; not actually used */

		/* tag call as internal */
		((slp_handle_impl_t *)hSLP)->internal_call = SLP_TRUE;

		(void) slp_unpackSrvReply(
			hSLP, reply, collate_scopes,
			&stree, &collator, &numResults);
		/* invoke last call */
		(void) slp_unpackSrvReply(
			hSLP, NULL, collate_scopes,
			&stree, &collator, &numResults);
		free(reply);

		/* revert internal call tag */
		((slp_handle_impl_t *)hSLP)->internal_call = SLP_FALSE;
	}

	/* Finally, if no results yet, try SA discovery */
	if (!stree) {
	    (void) SAAdvert_for_scopes(hSLP, &stree);
	}

	if (!stree) {
		/* found none, so just return "default" */
		if (!(*ppcScopes = strdup("default"))) {
			slp_err(LOG_CRIT, 0, "SLPFindScopes", "out of memory");
			return (SLP_MEMORY_ALLOC_FAILED);
		}
		return (SLP_OK);
	}

	/* we now have a btree, each leaf of which is a unique scope */
	slp_twalk(stree, collect_scopes, 0, (void *) ppcScopes);

	/* unescape scopes list */
	if ((err = slp_unescape(*ppcScopes, &unesc_reply, SLP_FALSE, '%'))
	    == SLP_OK) {
		free(*ppcScopes);
		*ppcScopes = unesc_reply;
	} else {
		free(unesc_reply);
	}

	return (err);
}

/*
 * Finds scopes according to the adminstrative scoping model. A
 * comma-seperated list of scopes is returned in *ppcScopes; the
 * caller must free *ppcScopes.
 * If the return_default parameter is true, and no scopes are found,
 * *ppcScopes will be set to 'default', otherwise, *ppcScopes will
 * be NULL. This helps simplify internal memory management.
 */
SLPError slp_administrative_scopes(char **ppcScopes,
					SLPBoolean return_default) {
	const char *useScopes;

	*ppcScopes = NULL;

	/* @@@ first try DHCP */
	/* next try the useScopes property */
	useScopes = SLPGetProperty(SLP_CONFIG_USESCOPES);

	if (useScopes && *useScopes) {
		if (!(*ppcScopes = strdup(useScopes))) {
			slp_err(LOG_CRIT, 0, "SLPFindScopes", "out of memory");
			return (SLP_MEMORY_ALLOC_FAILED);
		}
		return (SLP_OK);
	}

	/* found none, so just return "default" */
	if (return_default && !(*ppcScopes = strdup("default"))) {
		slp_err(LOG_CRIT, 0, "SLPFindScopes", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	return (SLP_OK);
}

/*
 * This function operates on the same btree as the collate_scopes().
 * The difference is that this one is called for each
 * SAAdvert recieved.
 */
/* ARGSUSED */
static SLPBoolean saadvert_callback(SLPHandle hp, char *scopes,
					SLPError err, void **stree) {
	char *s, *tstate;

	if (err != SLP_OK) {
		return (SLP_TRUE);
	}

	for (
		s = strtok_r((char *)scopes, ",", &tstate);
		s;
		s = strtok_r(NULL, ",", &tstate)) {

		char *ascope, **srch;

		if (!(ascope = strdup(s))) {	/* no memory! */
			slp_err(LOG_CRIT, 0, "collate_scopes",
				"out of memory");
			return (SLP_TRUE);
		}

		srch = slp_tsearch(
			(void *) ascope, stree,
			(int (*)(const void *, const void *)) slp_strcasecmp);
		if (*srch != ascope)
			/* scope is already in there, so just free ascope */
			free(ascope);
	}

	return (SLP_TRUE);
}

/*
 * Generates an SAAdvert solicitation, and returns any scopes found
 * from all recieved SAAdverts in stree. stree must be a btree
 * structure.
 */
static SLPError SAAdvert_for_scopes(SLPHandle hSLP, void **stree) {
	SLPError err;
	SLPBoolean sync_state;
	slp_handle_impl_t *hp = (slp_handle_impl_t *)hSLP;
	char *predicate;
	const char *type_hint;

	/* get type hint, if set */
	if ((type_hint = SLPGetProperty(SLP_CONFIG_TYPEHINT)) != NULL &&
		*type_hint != 0) {

		size_t hintlen = strlen(type_hint);
		size_t predlen = strlen("(service-type=)");

		/* check bounds */
		if (hintlen > (SLP_MAX_STRINGLEN - predlen)) {
			return (SLP_PARAMETER_BAD);
		}
		if (!(predicate = malloc(hintlen + predlen + 1))) {
			slp_err(LOG_CRIT, 0, "SAAdvert_for_scopes",
				"out of memory");
			return (SLP_MEMORY_ALLOC_FAILED);
		}
		(void) strcpy(predicate, "(service-type=");
		(void) strcat(predicate, type_hint);
		(void) strcat(predicate, ")");
	} else {
		predicate = "";
		type_hint = NULL;
	}

	/* No callback for SLPFindScopes, so force synchronous mode only */
	sync_state = hp->async;
	hp->async = SLP_FALSE;

	if ((err = slp_start_call(hp)) != SLP_OK)
		return (err);

	err = slp_packSrvRqst("service:service-agent", predicate, hp);

	if (err == SLP_OK) {
		err = slp_ua_common(hSLP, "",
		    (SLPGenericAppCB *)(uintptr_t)saadvert_callback,
		    stree,
		    (SLPMsgReplyCB *)unpackSAAdvert_scope);
	}

	if (type_hint) {
		free(predicate);
	}

	if (err != SLP_OK)
		slp_end_call(hp);

	/* restore sync state */
	hp->async = sync_state;

	return (err);
}

/*
 * Unpack an SAAdvert and pass each set of scopes into cb.
 */
/* ARGSUSED */
static SLPBoolean unpackSAAdvert_scope(slp_handle_impl_t *hSLP, char *reply,
					SLPScopeCallback cb, void *cookie,
					void **collator, int *numResults) {
	char *surl, *scopes, *attrs;
	SLPBoolean cont;

	if (!reply) {
		cb(hSLP, NULL, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	/* tag call as internal; gets all scopes, regardless of maxResults */
	hSLP->internal_call = SLP_TRUE;

	if (slp_unpackSAAdvert(reply, &surl, &scopes, &attrs) != SLP_OK) {
		return (SLP_TRUE);
	}

	cont = cb(hSLP, scopes, SLP_OK, cookie);

	/* revert internal_call tag */
	hSLP->internal_call = SLP_FALSE;

	free(surl);
	free(scopes);
	free(attrs);

	return (cont);
}

/*
 * Creates a service request for finding DAs or SAs (based on 'filter'),
 * and sends it to slpd, returning the reply in 'reply'.
 */
SLPError slp_find_das(const char *filter, char **reply) {
	SLPError err;
	char *msg, hostname[MAXHOSTNAMELEN];

	/* Try the cache first */
	if (*reply = slp_find_das_cached(filter)) {
		return (SLP_OK);
	}

	/*
	 * create a find scopes message:
	 * this is a SrvRqst for the type directory-agent.sun.
	 */
	/* use the local host's name for the scope */
	(void) gethostname(hostname, MAXHOSTNAMELEN);

	err = slp_packSrvRqst_single(
		SLP_SUN_DA_TYPE, hostname, filter, &msg, "en");

	if (err == SLP_OK) {
		err = slp_send2slpd(msg, reply);
		free(msg);
	}

	/* Add the reply to the cache */
	if (err == SLP_OK) {
		slp_put_das_cached(filter, *reply, slp_get_length(*reply));
	}

	return (err);
}

/*
 * This is called for each URL entry in the DA service reply (sun private).
 * Contained within the cookie is a btree, to which it adds new
 * scopes from the URL entry. The scopes are retrieved from the btree
 * by traversing the tree in SLPFindScopes().
 * SLPHandle h is NULL, so don't touch it!
 */
/*ARGSUSED*/
static SLPBoolean collate_scopes(SLPHandle h, const char *u,
					unsigned short lifetime,
					SLPError errCode, void *cookie) {
	SLPSrvURL *surl;
	char *s, *tstate, *p, *url;
	void **collator = cookie;

	if (errCode != SLP_OK)
		return (SLP_TRUE);

	/* dup url so as not to corrupt da cache */
	if (!(url = strdup(u))) {
		slp_err(LOG_CRIT, 0, "collate_scopes", "out of memory");
		return (SLP_FALSE);
	}

	/* parse url into a SLPSrvURL struct */
	if (SLPParseSrvURL(url, &surl) != SLP_OK)
		return (SLP_TRUE);	/* bad URL; skip it */

	/* collate the scopes using the btree stree->scopes: */
	/* skip the 'scopes=' part */
	if (!(p = strchr(surl->s_pcSrvPart, '='))) {
		free(surl);
		return (SLP_TRUE);	/* bad URL; skip it */
	}
	p++;

	for (
		s = strtok_r(p, ",", &tstate);
		s;
		s = strtok_r(NULL, ",", &tstate)) {

		char *ascope, **srch;

		if (!(ascope = strdup(s))) {	/* no memory! */
			slp_err(LOG_CRIT, 0, "collate_scopes",
				"out of memory");
			free(surl);
			return (SLP_TRUE);
		}

		srch = slp_tsearch(
			(void *) ascope, collator,
			(int (*)(const void *, const void *)) slp_strcasecmp);
		if (*srch != ascope)
			/* scope is already in there, so just free ascope */
			free(ascope);
	}

	free(url);
	free(surl);

	return (SLP_TRUE);
}

/*
 * Each time we visit a node for the last time, copy that scope into
 * the scope collection and free the scope string and the node.
 */
/*ARGSUSED*/
static void collect_scopes(void *node, VISIT order, int level, void *cookie) {
	char **scopes = (char **)cookie;

	if (order == endorder || order == leaf) {
		char *s = *(char **)node;
		slp_add2list(s, scopes, SLP_FALSE);
		free(s);
		free(node);
	}
}

void SLPFree(void *pvMem) {
	if (pvMem)
		free(pvMem);
}

/*
 * Escape / Unescape
 */

#define	isBadTagChar(c)	((c) == '*' || (c) == '_' || \
			(c) == '\n' || (c) == '\t' || (c) == '\r')

#define	isReserved(c)	((c) <= 31 || (c) == '(' || (c) == ')' || \
			(c) == ',' || (c) == '\\' || (c) == '!' || \
			(c) == '<' || (c) == '=' || (c) == '>' || \
			(c) == '~')

SLPError SLPEscape(const char *pcInbuf, char **ppcOutBuf, SLPBoolean isTag) {
	char *buf, *pin, *pout;

	if (!pcInbuf || !ppcOutBuf)
		return (SLP_PARAMETER_BAD);

	if (!(buf = malloc(strlen(pcInbuf) * 3 + 1))) {
		slp_err(LOG_CRIT, 0, "SLPEscape", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	*ppcOutBuf = buf;

	for (pin = (char *)pcInbuf, pout = buf; *pin; ) {
		int len;

		/* If char is start of multibyte char, just copy it in */
		if ((len = mblen(pin, MB_CUR_MAX)) > 1) {
			int i;
			for (i = 0; i < len && *pin; i++)
				*pout++ = *pin++;
			continue;
		}

		/* check for bad tag */
		if (isTag && isBadTagChar(*pin))
			return (SLP_PARSE_ERROR);

		if (isReserved(*pin)) {
			if (isTag)
				return (SLP_PARSE_ERROR);
			(void) sprintf(pout, "\\%.2x", *pin);
			pout += 3;
			pin++;
		} else {
			*pout++ = *pin++;
		}
	}
	*pout = 0;

	return (SLP_OK);
}

SLPError SLPUnescape(const char *pcInbuf, char **ppcOutBuf, SLPBoolean isTag) {
	if (!pcInbuf || !ppcOutBuf)
		return (SLP_PARAMETER_BAD);

	return (slp_unescape(pcInbuf, ppcOutBuf, isTag, '\\'));
}


/*
 * The actual unescaping routine; allows for different escape chars.
 */
static SLPError slp_unescape(const char *pcInbuf, char **ppcOutBuf,
				SLPBoolean isTag, const char esc_char) {
	char *buf, *pin, *pout, conv[3];

	if (!(buf = malloc(strlen(pcInbuf) * 3 + 1))) {
		slp_err(LOG_CRIT, 0, "SLPEscape", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	*ppcOutBuf = buf;

	conv[2] = 0;
	for (pin = (char *)pcInbuf, pout = buf; *pin; ) {
		int len;

		/* If char is start of multibyte char, just copy it in */
		if ((len = mblen(pin, MB_CUR_MAX)) > 1) {
			int i;
			for (i = 0; i < len && *pin; i++)
				*pout++ = *pin++;
			continue;
		}

		if (*pin == esc_char) {
			if (!pin[1] || !pin[2])
				return (SLP_PARSE_ERROR);
			pin++;
			conv[0] = *pin++;
			conv[1] = *pin++;
			*pout++ = (char)strtol(conv, NULL, 16);
			if (isTag && isBadTagChar(*pout))
				return (SLP_PARSE_ERROR);
		} else {
			*pout++ = *pin++;
		}
	}
	*pout = 0;

	return (SLP_OK);
}

/*
 * Properties
 *
 * All properties are stored in a global tree (prop_table). This
 * tree is created and accessed by slp_tsearch and slp_tfind.
 */
struct prop_entry {
	const char *key, *val;
};
typedef struct prop_entry slp_prop_entry_t;

/* Global properties table */
static void *slp_props = NULL;
static mutex_t prop_table_lock = DEFAULTMUTEX;

static void setDefaults();

static int compare_props(const void *a, const void *b) {
	return (strcmp(
		((slp_prop_entry_t *)a)->key,
		((slp_prop_entry_t *)b)->key));
}

void SLPSetProperty(const char *pcName, const char *pcValue) {
	slp_prop_entry_t *pe, **pe2;

	if (!slp_props) setDefaults();

	if (!pcName || !pcValue) {
		return;
	}

	if (!(pe = malloc(sizeof (*pe)))) {
		slp_err(LOG_CRIT, 0, "SLPSetProperty", "out of memory");
		return;
	}

	/* place the strings under library ownership */
	if (!(pe->key = strdup(pcName))) {
		free(pe);
		slp_err(LOG_CRIT, 0, "SLPSetProperty", "out of memory");
		return;
	}

	if (!(pe->val = strdup(pcValue))) {
		free((void *) pe->key);
		free(pe);
		slp_err(LOG_CRIT, 0, "SLPSetProperty", "out of memory");
		return;
	}

	/* is pcName already set? */
	(void) mutex_lock(&prop_table_lock);
	pe2 = slp_tsearch((void *) pe, &slp_props, compare_props);
	if (pe != *pe2) {
		/* this prop is already set; overwrite the old value */
		free((void *) (*pe2)->val);
		(*pe2)->val = pe->val;
		free((void *) pe->key);
		free(pe);
	}
	(void) mutex_unlock(&prop_table_lock);
}

const char *SLPGetProperty(const char *pcName) {
	slp_prop_entry_t pe[1], **ans;

	if (!slp_props) setDefaults();

	if (!pcName) {
		return (NULL);
	}

	pe->key = pcName;

	(void) mutex_lock(&prop_table_lock);
	ans = slp_tfind(pe, &slp_props, compare_props);
	(void) mutex_unlock(&prop_table_lock);
	if (ans)
		return ((*ans)->val);
	return (NULL);
}

static void setDefaults() {
	slp_prop_entry_t *pe;
	static mutex_t lock = DEFAULTMUTEX;

	(void) mutex_lock(&lock);
	if (slp_props) {
		(void) mutex_unlock(&lock);
		return;
	}

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_ISBROADCASTONLY);
	pe->val = strdup("false");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_MULTICASTTTL);
	pe->val = strdup("255");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_MULTICASTMAXWAIT);
	pe->val = strdup("15000");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_DATAGRAMTIMEOUTS);
	pe->val = strdup("2000,2000,2000");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_MULTICASTTIMEOUTS);
	pe->val = strdup("1000,3000,3000,3000,3000");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = SLP_CONFIG_MTU; pe->val = "1400";
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_MAXRESULTS);
	pe->val = strdup("-1");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_SECURITY_ON);
	pe->val = strdup("false");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	pe = malloc(sizeof (*pe));
	pe->key = strdup(SLP_CONFIG_BYPASS_AUTH);
	pe->val = strdup("false");
	(void) slp_tsearch((void *) pe, &slp_props, compare_props);

	slp_readConfig();

	(void) mutex_unlock(&lock);
}

static const char *error_strings[] = {
	"OK",				/* 0 */
	"Language not supported",	/* -1 */
	"Parse error",			/* -2 */
	"Invalid registration",		/* -3 */
	"Scope not supported",		/* -4 */
	"Invalid error number",		/* -5 */
	"Authentication absent",	/* -6 */
	"Authentication failed",	/* -7 */
	"Invalid error number",		/* -8 */
	"Invalid error number",		/* -9 */
	"Invalid error number",		/* -10 */
	"Invalid error number",		/* -11 */
	"Invalid error number",		/* -12 */
	"Invalid update",		/* -13 */
	"Invalid error number",		/* -14 */
	"Invalid error number",		/* -15 */
	"Invalid error number",		/* -16 */
	"Not implemented",		/* -17 */
	"Buffer overflow",		/* -18 */
	"Network timed out",		/* -19 */
	"Network init failed",		/* -20 */
	"Memory alloc failed",		/* -21 */
	"Parameter bad",		/* -22 */
	"Network error",		/* -23 */
	"Internal system error",	/* -24 */
	"Handle in use",		/* -25 */
	"Type error"			/* -26 */
};

#define	SLP_MAX_ERR_CNT	26

const char *slp_strerror(SLPError err) {
	int abserr;
	const char *str;

	if (err == SLP_LAST_CALL) {
		str = "Last call";
	} else if (err == SLP_SECURITY_UNAVAILABLE) {
		str = "Security Implementation Unavailable";
	} else {
		abserr = abs(err);
		if (abserr > SLP_MAX_ERR_CNT) {
			str = "Invalid error number";
		} else {
			str = error_strings[abserr];
		}
	}

	return (dgettext("libslp", str));
}
