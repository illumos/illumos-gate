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

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <slp-internal.h>

struct surl_node {
	char *surl;
	unsigned short lifetime;
};

struct caller_bundle {
	SLPSrvURLCallback *cb;
	void *cookie;
	SLPHandle handle;
};

static int compare_surls(struct surl_node *, struct surl_node *);
static char *collate_surls(char *, unsigned short, void **);
static void traverse_surls(SLPHandle, SLPSrvURLCallback, void *, void *);
static void process_surl_node(void *, VISIT, int, void *);
static SLPBoolean unpackDAAdvert_srv(slp_handle_impl_t *, char *,
					SLPSrvURLCallback, void *,
					void **, int *);
static SLPBoolean unpackSAAdvert_srv(slp_handle_impl_t *, char *,
					SLPSrvURLCallback, void *,
					void **, int *);

SLPError SLPFindSrvs(SLPHandle hSLP, const char *pcServiceType,
			const char *pcScope, const char *pcSearchFilter,
			SLPSrvURLCallback callback, void *pvUser) {
	SLPError err;
	slp_handle_impl_t *hp = (slp_handle_impl_t *)hSLP;
	int wantSAAdvert =
		strcasecmp(pcServiceType, "service:service-agent") == 0;
	int wantDAAdvert =
		strcasecmp(pcServiceType, "service:directory-agent") == 0;
	int isSpecial = wantSAAdvert || wantDAAdvert;
	SLPMsgReplyCB *unpack_cb;

	if (!hSLP || !pcServiceType || !pcScope || (!*pcScope && !isSpecial) ||
	    !pcSearchFilter || !callback) {
		return (SLP_PARAMETER_BAD);
	}

	if ((strlen(pcServiceType) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcScope) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcSearchFilter) > SLP_MAX_STRINGLEN)) {
	    return (SLP_PARAMETER_BAD);
	}

	if ((err = slp_start_call(hSLP)) != SLP_OK)
		return (err);

	/* Special unpacker for DA and SA solicitations */
	if (wantDAAdvert) {
		unpack_cb = (SLPMsgReplyCB *)unpackDAAdvert_srv;
		hp->force_multicast = SLP_TRUE;
	} else if (wantSAAdvert) {
		unpack_cb = (SLPMsgReplyCB *)unpackSAAdvert_srv;
		hp->force_multicast = SLP_TRUE;
	} else {
		/* normal service request */
		unpack_cb = (SLPMsgReplyCB *)slp_unpackSrvReply;
	}

	err = slp_packSrvRqst(pcServiceType, pcSearchFilter, hp);

	if (err == SLP_OK)
		err = slp_ua_common(hSLP, pcScope,
		    (SLPGenericAppCB *)(uintptr_t)callback, pvUser, unpack_cb);
	if (err != SLP_OK)
		slp_end_call(hSLP);

	return (err);
}

SLPBoolean slp_unpackSrvReply(slp_handle_impl_t *hp, char *reply,
				SLPSrvURLCallback cb, void *cookie,
				void **collator, int *numResults) {
	SLPError errCode;
	unsigned short urlCount, protoErrCode;
	size_t len, off;
	int i;
	int maxResults = slp_get_maxResults();
	SLPBoolean cont = SLP_TRUE;

	if (!reply) {
		/* no more results */
		/* traverse_surls:invoke cb for sync case,and free resources */
		if (!hp->async) {
		    traverse_surls(hp, cb, cookie, *collator);
		}
		cb(hp, NULL, 0, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	len = slp_get_length(reply);
	off = SLP_HDRLEN + slp_get_langlen(reply);
	/* err code */
	if (slp_get_sht(reply, len, &off, &protoErrCode) != SLP_OK)
		return (SLP_TRUE);
	/* internal errors should have been filtered out by the net code */
	if ((errCode = slp_map_err(protoErrCode)) != SLP_OK) {
		return (cb(hp, NULL, 0, errCode, cookie));
	}

	/* url entry count */
	if (slp_get_sht(reply, len, &off, &urlCount) != SLP_OK)
		return (SLP_TRUE);

	/* for each srvRply, unpack and pass to CB */
	for (i = 0; i < urlCount && !hp->cancel; i++) {
		char *pcSrvURL;
		unsigned short sLifetime;
		int nURLAuthBlocks;
		size_t tbv_len;
		char *url_tbv;

		/* parse URL entry into params */
		off++;	/* skip reserved byte */
		/* lifetime */
		if (slp_get_sht(reply, len, &off, &sLifetime) != SLP_OK)
			return (SLP_TRUE);
		/* URL itself; keep track of it in case we need to verify */
		url_tbv = reply + off;
		tbv_len = off;
		if (slp_get_string(reply, len, &off, &pcSrvURL) != SLP_OK)
			return (SLP_TRUE);
		tbv_len = off - tbv_len;

		/* number of url auths */
		if (slp_get_byte(reply, len, &off, &nURLAuthBlocks) != SLP_OK)
			goto cleanup;

		/* get and verify auth blocks */
		if ((!hp->internal_call && slp_get_security_on()) ||
		    nURLAuthBlocks > 0) {
			struct iovec iov[1];
			size_t abLen = 0;

			iov[0].iov_base = url_tbv;
			iov[0].iov_len = tbv_len;

			if (slp_verify(iov, 1,
					reply + off,
					len - off,
					nURLAuthBlocks,
					&abLen) != SLP_OK) {
			    goto cleanup;
			}
			off += abLen;
		}

		/* collate the srv urls for sync behavior */
		if (!hp->async) {
		    pcSrvURL = collate_surls(pcSrvURL, sLifetime, collator);

		    if (!pcSrvURL)
			continue;
		}

		(*numResults)++;
		/* invoke cb */
		if (hp->async)
			cont = cb(
				(SLPHandle) hp,
				pcSrvURL,
				sLifetime,
				errCode,
				cookie);

		/* cleanup */
cleanup:
		free(pcSrvURL);

		/* check maxResults */
		if (!hp->internal_call && *numResults == maxResults) {
			cont = SLP_FALSE;
		}

		if (!cont) break;
	}

	return (cont);
}

/*
 * unpackDAAdvert_srv follows the same same logic flow as slp_unpackSrvReply
 * with two differences: the message in reply is a DAAdvert, and
 * this function is not used internally, so hp is never NULL. Although
 * all info from a DAAdvert is returned by slp_unpackDAAdvert, here
 * the recipient (the user-supplied SLPSrvURLCallback) is interested
 * only in the DA service URL.
 */
static SLPBoolean unpackDAAdvert_srv(slp_handle_impl_t *hp, char *reply,
					SLPSrvURLCallback cb, void *cookie,
					void **collator, int *numResults) {
	char *surl, *scopes, *attrs, *spis;
	SLPBoolean cont = SLP_TRUE;
	SLPError errCode;
	int maxResults = slp_get_maxResults();

	if (!reply) {
		/* no more results */
		/* traverse_surls:invoke cb for sync case,and free resources */
		if (!hp->async) {
			traverse_surls(hp, cb, cookie, *collator);
		}
		cb(hp, NULL, 0, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	if (slp_unpackDAAdvert(reply, &surl, &scopes, &attrs, &spis, &errCode)
	    != SLP_OK) {
		return (SLP_TRUE);
	}
	if (errCode != SLP_OK) {
		return (cb(hp, NULL, 0, errCode, cookie));
	}

	/* collate the urls */
	surl = collate_surls(surl, 0, collator);
	if (!surl) {
		return (SLP_TRUE);
	}

	(*numResults)++;
	if (hp->async) {
		cont = cb((SLPHandle)hp, surl, 0, errCode, cookie);
	}

	/* cleanup */
	free(surl);
	free(scopes);
	free(attrs);
	free(spis);

	/* check maxResults */
	if (!hp->internal_call && *numResults == maxResults) {
		return (SLP_FALSE);
	}

	return (cont);
}
/*
 * unpackSAAdvert_srv follows the same same logic flow as slp_unpackSrvReply
 * with two differences: the message in reply is a SAAdvert, and
 * this function is not used internally, so hp is never NULL. Although
 * all info from an SAAdvert is returned by slp_unpackSAAdvert, here
 * the recipient (the user-supplied SLPSrvURLCallback) is interested
 * only in the SA service URL.
 */
static SLPBoolean unpackSAAdvert_srv(slp_handle_impl_t *hp, char *reply,
					SLPSrvURLCallback cb, void *cookie,
					void **collator, int *numResults) {
	char *surl, *scopes, *attrs;
	SLPBoolean cont = SLP_TRUE;
	int maxResults = slp_get_maxResults();

	if (!reply) {
		/* no more results */
		/* traverse_surls:invoke cb for sync case,and free resources */
		if (!hp->async) {
			/* sync case */
			traverse_surls(hp, cb, cookie, *collator);
		}
		cb(hp, NULL, 0, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	if (slp_unpackSAAdvert(reply, &surl, &scopes, &attrs) != SLP_OK) {
		return (SLP_TRUE);
	}

	/* collate the urls */
	surl = collate_surls(surl, 0, collator);
	if (!surl) {
		return (SLP_TRUE);
	}

	(*numResults)++;
	if (hp->async) {
		cont = cb((SLPHandle)hp, surl, 0, SLP_OK, cookie);
	}

	/* cleanup */
	free(surl);
	free(scopes);
	free(attrs);

	/* check maxResults */
	if (!hp->internal_call && *numResults == maxResults) {
		return (SLP_FALSE);
	}

	return (cont);
}

SLPError slp_packSrvRqst(const char *type,
				const char *filter,
				slp_handle_impl_t *hp) {
	SLPError err;
	size_t len, msgLen, tmplen;
	slp_msg_t *msg = &(hp->msg);
	char *spi = NULL;

	if (slp_get_security_on()) {
	    spi = (char *)SLPGetProperty(SLP_CONFIG_SPI);
	}

	if (!spi || !*spi) {
		spi = "";
	}

	/*
	 * Allocate iovec for the messge. A SrvRqst is layed out thus:
	 *  0: header
	 *  1: prlist length
	 *  2: prlist (filled in later by networking code)
	 *  3: service type string
	 *  4: scopes length
	 *  5: scopes (filled in later by networking code)
	 *  6: predicate string and SPI string
	 */
	if (!(msg->iov = calloc(7, sizeof (*(msg->iov))))) {
		slp_err(LOG_CRIT, 0, "slp_packSrvRqst", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	msg->iovlen = 7;

	/* calculate msg length */
	msgLen = 2 +		/* prlist length */
	    2 + strlen(type) +	/* service type */
	    2 +			/* scope list length */
	    2 + strlen(filter) + /* predicate string */
	    2 + strlen(spi);	/* SPI string */

	if (!(msg->msg = calloc(1, msgLen))) {
		free(msg->iov);
		slp_err(LOG_CRIT, 0, "slp_packSrvRqst", "out of memory");
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

	/* Add type string */
	msg->iov[3].iov_base = msg->msg + len;
	tmplen = len;

	err = slp_add_string(msg->msg, msgLen, type, &len);
	msg->iov[3].iov_len = len - tmplen;

	if (err != SLP_OK)
		goto error;

	/* Add search filter */
	msg->iov[6].iov_base = msg->msg + len;
	tmplen = len;

	err = slp_add_string(msg->msg, msgLen, filter, &len);
	if (err != SLP_OK)
		goto error;

	err = slp_add_string(msg->msg, msgLen, spi, &len);

	msg->iov[6].iov_len = len - tmplen;

	hp->fid = SRVRQST;

	if (err == SLP_OK) {
		return (err);
	}

	/* else error */
error:
	free(msg->iov);
	free(msg->msg);

	return (err);
}

/*
 * Caller must free msg
 */
SLPError slp_packSrvRqst_single(const char *type,
				const char *scopes,
				const char *filter,
				char **msg,
				const char *lang) {
	SLPError err;
	size_t len, msgLen;

	msgLen =
		SLP_HDRLEN + strlen(lang) + 2 +
		2 + strlen(type) +
		2 + strlen(scopes) +
		2 + strlen(filter) +
		2; /* No SPI string for internal calls */

	if (!(*msg = calloc(msgLen, 1))) {
		slp_err(LOG_CRIT, 0, "slp_packSrvRqst_single",
			"out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	len = 0;
	err = slp_add_header(lang, *msg, msgLen, SRVRQST, msgLen, &len);

	len += 2;	/* empty PR list */

	if (err == SLP_OK)
		err = slp_add_string(*msg, msgLen, type, &len);
	if (err == SLP_OK)
		err = slp_add_string(*msg, msgLen, scopes, &len);
	if (err == SLP_OK)
		err = slp_add_string(*msg, msgLen, filter, &len);
	if (err == SLP_OK)
		/* empty SPI string */
		err = slp_add_string(*msg, msgLen, "", &len);

	return (err);
}


static int compare_surls(struct surl_node *s1, struct surl_node *s2) {
	if (s1->lifetime != s2->lifetime)
		return (s1->lifetime - s2->lifetime);
	return (slp_strcasecmp(s1->surl, s2->surl));
}

/*
 * Using the collator, determine if this URL has already been processed.
 * If so, free surl and return NULL, else return the URL.
 */
static char *collate_surls(char *surl, unsigned short life, void **collator) {
	struct surl_node *n, **res;

	if (!(n = malloc(sizeof (*n)))) {
		slp_err(LOG_CRIT, 0, "collate_surls", "out of memory");
		return (NULL);
	}
	if (!(n->surl = strdup(surl))) {
		free(n);
		slp_err(LOG_CRIT, 0, "collate_surls", "out of memory");
		return (NULL);
	}
	n->lifetime = life;
	res = slp_tsearch((void *) n, collator,
			(int (*)(const void *, const void *)) compare_surls);
	if (*res == n) {
		/* first time we've encountered this url */
		return (surl);
	}
	/* else  already in tree */
	free(n->surl);
	free(n);
	free(surl);
	return (NULL);
}

static void traverse_surls(SLPHandle h, SLPSrvURLCallback cb,
				void *cookie, void *collator) {
	struct caller_bundle caller[1];

	if (!collator)
		return;
	caller->cb = cb;
	caller->cookie = cookie;
	caller->handle = h;
	slp_twalk(collator, process_surl_node, 0, caller);
}

/*ARGSUSED*/
static void process_surl_node(void *node, VISIT order, int level, void *c) {
	struct surl_node *n;
	SLPSrvURLCallback *cb;
	slp_handle_impl_t *h;
	struct caller_bundle *caller = (struct caller_bundle *)c;

	if (order == endorder || order == leaf) {
		SLPBoolean cont = SLP_TRUE;

		cb = caller->cb;
		h = (slp_handle_impl_t *)caller->handle;
		n = *(struct surl_node **)node;
		/* invoke cb */
		if (cont && (!h || !h->async))
			cont = cb(
				h, n->surl,
				n->lifetime,
				SLP_OK,
				caller->cookie);

		free(n->surl);
		free(n);
		free(node);
	}
}
