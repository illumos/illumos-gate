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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <syslog.h>
#include <slp-internal.h>

static SLPBoolean UnpackSrvTypesReply(slp_handle_impl_t *, char *,
					SLPSrvTypeCallback, void *,
					void **, int *);
static SLPError slp_packSrvTypeRqst(slp_handle_impl_t *, const char *);
static char *collate_types(char *, void **, int *, int);
static char *build_types_list(void *);
static void collect_types(void *, VISIT, int, void *);

SLPError SLPFindSrvTypes(SLPHandle hSLP, const char *pcNamingAuthority,
				const char *pcScopeList,
				SLPSrvTypeCallback callback, void *pvUser) {
	SLPError err;

	if (!hSLP || !pcNamingAuthority || !pcScopeList ||
	    !*pcScopeList || !callback) {
		return (SLP_PARAMETER_BAD);
	}

	if ((strlen(pcNamingAuthority) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcScopeList) > SLP_MAX_STRINGLEN)) {
	    return (SLP_PARAMETER_BAD);
	}

	if ((err = slp_start_call(hSLP)) != SLP_OK)
		return (err);

	/* format params into msgBuf */
	err = slp_packSrvTypeRqst(hSLP, pcNamingAuthority);

	if (err == SLP_OK)
		err = slp_ua_common(hSLP, pcScopeList,
		    (SLPGenericAppCB *)(uintptr_t)callback, pvUser,
		    (SLPMsgReplyCB *) UnpackSrvTypesReply);

	if (err != SLP_OK)
		slp_end_call(hSLP);

	return (err);
}

static SLPBoolean UnpackSrvTypesReply(slp_handle_impl_t *hp, char *reply,
					SLPSrvTypeCallback cb, void *cookie,
					void **collator, int *numResults) {
	char *pcSrvTypes;
	SLPError errCode;
	unsigned short protoErrCode;
	size_t off, len;
	int maxResults = slp_get_maxResults();
	SLPBoolean cont = SLP_TRUE;

	if (!reply) {
		/* no more results */
		if (!hp->async) {
		    pcSrvTypes = build_types_list(*collator);
		}

		if (!hp->async && pcSrvTypes) {
		    /* synchronous case */
		    cb(hp, pcSrvTypes, SLP_OK, cookie);
		    free(pcSrvTypes);
		}
		cb(hp, NULL, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	/* parse reply into params */
	len = slp_get_length(reply);
	off = SLP_HDRLEN + slp_get_langlen(reply);
	/* error code */
	if (slp_get_sht(reply, len, &off, &protoErrCode) != SLP_OK)
		return (SLP_TRUE);
	/* internal errors should have been filtered out by the net code */
	if ((errCode = slp_map_err(protoErrCode)) != SLP_OK) {
		return (cb(hp, NULL, errCode, cookie));
	}

	/* types string */
	if (slp_get_string(reply, len, &off, &pcSrvTypes) != SLP_OK)
		return (SLP_TRUE);

	/* collate the types for sync behavior */
	if (!hp->async) {
	    pcSrvTypes = collate_types(pcSrvTypes, collator,
					numResults, maxResults);
	    if (!pcSrvTypes)
		return (SLP_TRUE);
	} else {
	    /* async; invoke cb */
	    cont = cb((SLPHandle) hp, pcSrvTypes, errCode, cookie);
	}

	/* cleanup */
	free(pcSrvTypes);

	/* check maxResults */
	if (!hp->internal_call && *numResults == maxResults) {
		return (SLP_FALSE);
	}

	return (cont);
}

static SLPError slp_packSrvTypeRqst(slp_handle_impl_t *hp, const char *na) {
	SLPError err;
	size_t len, nalen, msgLen, tmplen;
	int all_nas;
	slp_msg_t *msg = &(hp->msg);

	/*
	 * Allocate iovec for the message. A SrvTypeRqst is layed out thus:
	 *  0: header
	 *  1: prlist length
	 *  2: prlist (filled in later by networking code)
	 *  3: na
	 *  4: scopes length
	 *  5: scopes (filled in later by networking code)
	 */
	if (!(msg->iov = calloc(6, sizeof (*(msg->iov))))) {
		slp_err(LOG_CRIT, 0, "slp_packSrvTypeRqst", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	msg->iovlen = 6;

	/* calculate msg length */
	all_nas = strcmp(na, "*") == 0 ? 1 : 0;
	if (all_nas) {
		nalen = 0;
	} else {
		nalen = strlen(na);
	}
	nalen += 2;

	msgLen = 2 +	/* prlist length */
	    nalen +	/* NA string */
	    2;		/* Scope string length */

	if (!(msg->msg = calloc(1, msgLen))) {
		free(msg->iov);
		slp_err(LOG_CRIT, 0, "slp_packSrvTypeRqst", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* set pointer to PR list and scope list length spaces */
	msg->prlistlen.iov_base = msg->msg;
	msg->prlistlen.iov_len = 2;
	msg->iov[1].iov_base = msg->msg;
	msg->iov[1].iov_len = 2;

	msg->scopeslen.iov_base = msg->msg + 2;
	msg->scopeslen.iov_len = 2;
	msg->iov[4].iov_base = msg->msg + 2;
	msg->iov[4].iov_len = 2;

	/* set up the scopes and prlist pointers into iov */
	msg->prlist = &(msg->iov[2]);
	msg->scopes = &(msg->iov[5]);

	len = 4;

	/* set up NA string in iovec */
	msg->iov[3].iov_base = msg->msg + len;
	tmplen = len;

	if (all_nas) {
		err = slp_add_sht(msg->msg, msgLen, 0xffff, &len);
	} else {
		err = slp_add_string(msg->msg, msgLen, na, &len);
	}
	msg->iov[3].iov_len = len - tmplen;

	hp->fid = SRVTYPERQST;
	if (err == SLP_OK) {
		return (SLP_OK);
	}

	/* else error */
	free(msg->iov);
	free(msg->msg);

	return (err);
}

/*
 * Using the collator, determines which types in the types list
 * have already been recieved, and composes a new list of the remaining
 * (unique) types. If there are no unique types, returns NULL;
 * types is destructively modified.
 */
static char *collate_types(char *types, void **collator,
				int *numResults, int maxResults) {
	char *p, *s, **res, *utypes = NULL;

	/* walk through the types list */
	p = types;
	for (s = types; p && *numResults != maxResults; s = p) {
		p = slp_utf_strchr(s, ',');
		if (p)
			*p++ = 0;
		if (!(s = strdup(s))) {
		    free(types);
		    if (utypes) free(utypes);
		    slp_err(LOG_CRIT, 0, "collate_types", "out of memory");
		    return (NULL);
		}
		/* search the tree for this type */
		res = slp_tsearch((void *) s, collator,
			(int (*)(const void *, const void *)) slp_strcasecmp);
		if (*res == s) {
			/* first time we've encountered this type */
			slp_add2list(s, &utypes, SLP_FALSE);
			(*numResults)++;
		} else {
			/* else  already in tree */
			free(s);
		}
	}
	free(types);
	return (utypes);
}

/*
 * This is used after all types have been collated into the tree.
 * It walks through the tree, composing a list from all the types in
 * the tree, and freeing each node of the tree as it goes.
 * Returns the list, or NULL if the tree is empty.
 */
/* the walk action function: */
/*ARGSUSED*/
static void collect_types(void *node, VISIT order, int level, void *cookie) {
	char **types = (char **)cookie;

	if (order == endorder || order == leaf) {
		char *t = *(char **)node;
		slp_add2list(t, types, SLP_FALSE);
		free(t);
		free(node);
	}
}

/* the walk driver: */
static char *build_types_list(void *collator) {
	char *types = NULL;

	if (!collator)
		return (NULL);
	slp_twalk(collator, collect_types, 0, (void *) &types);
	return (types);
}
