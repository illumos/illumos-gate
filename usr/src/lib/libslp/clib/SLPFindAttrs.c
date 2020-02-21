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

#include <stdlib.h>
#include <syslog.h>
#include <slp-internal.h>

struct attr_node {
	char *tag, *val;
};

static SLPError slp_packAttrRqst(slp_handle_impl_t *, const char *,
					const char *);
static int compare_tags(const void *, const void *);
static void collate_attrs(char *, void **, int *, int);
static void parens_attr(char *, void **, int *);
static void merge_attrs(struct attr_node *, char *);
static char *build_attrs_list(void *collator);
static void collect_attrs(void *, VISIT, int, void *);
static SLPBoolean unpackDAAdvert_attr(slp_handle_impl_t *, char *,
					SLPAttrCallback, void *,
					void **, int *);
static SLPBoolean unpackSAAdvert_attr(slp_handle_impl_t *, char *,
					SLPAttrCallback, void *,
					void **, int *);

SLPError SLPFindAttrs(SLPHandle hSLP, const char *pcURL, const char *pcScope,
			const char *pcAttrIds,
			SLPAttrCallback callback, void *pvUser) {
	SLPError err;
	int wantSAAdvert =
		strcasecmp(pcURL, "service:service-agent") == 0;
	int wantDAAdvert =
		strcasecmp(pcURL, "service:directory-agent") == 0;
	int isSpecial = wantSAAdvert || wantDAAdvert;
	SLPMsgReplyCB *unpack_cb;


	if (!hSLP || !pcURL || !pcScope || (!*pcScope && !isSpecial) ||
	    !pcAttrIds || !callback) {
		return (SLP_PARAMETER_BAD);
	}

	if ((strlen(pcURL) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcScope) > SLP_MAX_STRINGLEN) ||
	    (strlen(pcAttrIds) > SLP_MAX_STRINGLEN)) {
	    return (SLP_PARAMETER_BAD);
	}

	if ((err = slp_start_call(hSLP)) != SLP_OK)
		return (err);

	/* Special packer and unpacker for DA and SA solicitations */
	if (wantDAAdvert) {
		unpack_cb = (SLPMsgReplyCB *)unpackDAAdvert_attr;
		err = slp_packSrvRqst(pcURL, "", hSLP);
		((slp_handle_impl_t *)hSLP)->force_multicast = SLP_TRUE;
	} else if (wantSAAdvert) {
		unpack_cb = (SLPMsgReplyCB *)unpackSAAdvert_attr;
		err = slp_packSrvRqst(pcURL, "", hSLP);
		((slp_handle_impl_t *)hSLP)->force_multicast = SLP_TRUE;
	} else {
		/* normal service request */
		unpack_cb = (SLPMsgReplyCB *)slp_UnpackAttrReply;
		/* format params into msgBuf */
		err = slp_packAttrRqst(hSLP, pcURL, pcAttrIds);
	}

	if (err == SLP_OK)
		err = slp_ua_common(hSLP, pcScope,
		    (SLPGenericAppCB *)(uintptr_t)callback, pvUser, unpack_cb);

	if (err != SLP_OK)
		slp_end_call(hSLP);

	return (err);
}

SLPBoolean slp_UnpackAttrReply(slp_handle_impl_t *hp, char *reply,
				SLPAttrCallback cb, void *cookie,
				void **collator, int *numResults) {
	char *pcAttrList;
	SLPError errCode;
	unsigned short protoErrCode;
	size_t len, off;
	int maxResults = slp_get_maxResults();
	SLPBoolean cont = SLP_TRUE;
	int auth_cnt;
	size_t tbv_len;
	char *attr_tbv;

	if (!reply) {
		/* no more results */
		if (!hp->async) {
		    pcAttrList = build_attrs_list(*collator);
		}

		if (!hp->async && pcAttrList) {
		    cb(hp, pcAttrList, SLP_OK, cookie);
		    free(pcAttrList);
		}
		cb(hp, NULL, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	/* parse reply into params */
	len = slp_get_length(reply);
	off = SLP_HDRLEN + slp_get_langlen(reply);
	/* err code */
	if (slp_get_sht(reply, len, &off, &protoErrCode) != SLP_OK)
		return (SLP_TRUE);
	/* internal errors should have been filtered out by the net code */
	if ((errCode = slp_map_err(protoErrCode)) != SLP_OK) {
		return (cb(hp, NULL, errCode, cookie));
	}

	/* attr list */
	attr_tbv = reply + off;
	tbv_len = off;
	if (slp_get_string(reply, len, &off, &pcAttrList) != SLP_OK)
		return (SLP_TRUE);
	tbv_len = off - tbv_len;

	/* number of attr auths */
	if (slp_get_byte(reply, len, &off, &auth_cnt) != SLP_OK) {
	    goto cleanup;
	}

	/* get and verify auth blocks */
	if ((!hp->internal_call && slp_get_security_on()) || auth_cnt > 0) {
		size_t abLen = 0;
		struct iovec iov[1];

		iov[0].iov_base = attr_tbv;
		iov[0].iov_len = tbv_len;

		if (slp_verify(iov, 1,
				reply + off,
				len - off,
				auth_cnt,
				&abLen) != SLP_OK) {
		    goto cleanup;
		}
	}

	/* collate */
	if (!hp->async) {
		collate_attrs(pcAttrList, collator, numResults, maxResults);
	} else {
		/* async: invoke cb */
		cont = cb((SLPHandle) hp, pcAttrList, errCode, cookie);
		(*numResults)++;
	}

cleanup:
	free(pcAttrList);

	/* check maxResults */
	if (!hp->internal_call && *numResults == maxResults) {
		return (SLP_FALSE);
	}

	return (cont);
}

/*
 * unpackDAAdvert_attr follows the same logic stream as UnpackAttrReply,
 * except that reply contains a DAAdvert.
 */
static SLPBoolean unpackDAAdvert_attr(slp_handle_impl_t *hp, char *reply,
					SLPAttrCallback cb, void *cookie,
					void **collator, int *numResults) {
	char *surl, *scopes, *attrs, *spis;
	SLPBoolean cont = SLP_TRUE;
	SLPError errCode;
	int maxResults = slp_get_maxResults();

	if (!reply) {
		/* no more results */
		if (!hp->async) {
		    attrs = build_attrs_list(*collator);
		}

		if (!hp->async && attrs) {
			cb(hp, attrs, SLP_OK, cookie);
			free(attrs);
		}
		cb(hp, NULL, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	if (slp_unpackDAAdvert(reply, &surl, &scopes, &attrs, &spis, &errCode)
	    != SLP_OK) {
		return (SLP_TRUE);
	}
	if (errCode != SLP_OK) {
		return (cb(hp, NULL, errCode, cookie));
	}

	/* collate */
	if (!hp->async) {
		collate_attrs(attrs, collator, numResults, maxResults);
	} else {
		/* async: invoke cb */
		cont = cb((SLPHandle) hp, attrs, errCode, cookie);
		(*numResults)++;
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
 * unpackSAAdvert_attr follows the same logic stream as UnpackAttrReply,
 * except that reply contains an SAAdvert.
 */
static SLPBoolean unpackSAAdvert_attr(slp_handle_impl_t *hp, char *reply,
					SLPAttrCallback cb, void *cookie,
					void **collator, int *numResults) {
	char *surl, *scopes, *attrs;
	SLPBoolean cont = SLP_TRUE;
	int maxResults = slp_get_maxResults();

	if (!reply) {
		/* no more results */
		if (!hp->async) {
		    attrs = build_attrs_list(*collator);
		}

		if (!hp->async && attrs) {
			cb(hp, attrs, SLP_OK, cookie);
			free(attrs);
		}
		cb(hp, NULL, SLP_LAST_CALL, cookie);
		return (SLP_FALSE);
	}

	if (slp_unpackSAAdvert(reply, &surl, &scopes, &attrs) != SLP_OK) {
		return (SLP_TRUE);
	}

	/* collate */
	if (!hp->async) {
		collate_attrs(attrs, collator, numResults, maxResults);
	} else {
		/* async: invoke cb */
		cont = cb((SLPHandle) hp, attrs, SLP_OK, cookie);
		(*numResults)++;
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

static SLPError slp_packAttrRqst(slp_handle_impl_t *hp, const char *url,
					const char *ids) {
	SLPError err;
	size_t len, tmplen, msgLen;
	slp_msg_t *msg = &(hp->msg);
	char *spi = NULL;

	if (slp_get_security_on()) {
	    spi = (char *)SLPGetProperty(SLP_CONFIG_SPI);
	}

	if (!spi || !*spi) {
		spi = "";
	}

	/*
	 * Allocate iovec for the messge. An AttrRqst is layed out thus:
	 *  0: header
	 *  1: prlist length
	 *  2: prlist (filled in later by networking code)
	 *  3: URL string
	 *  4: scopes length
	 *  5: scopes (filled in later by networking code)
	 *  6: tag list string and SPI string
	 */
	if (!(msg->iov = calloc(7, sizeof (*(msg->iov))))) {
		slp_err(LOG_CRIT, 0, "slp_packAttrRqst", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	msg->iovlen = 7;

	/* calculate msg length */
	msgLen = 2 +		/* prlist length */
	    2 + strlen(url) +	/* URL */
	    2 +			/* scope list length */
	    2 + strlen(ids) +	/* tag list */
	    2 + strlen(spi);	/* SPI string */

	if (!(msg->msg = calloc(1, msgLen))) {
		free(msg->iov);
		slp_err(LOG_CRIT, 0, "slp_packAttrRqst", "out of memory");
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

	/* Add URL string */
	msg->iov[3].iov_base = msg->msg + len;
	tmplen = len;

	err = slp_add_string(msg->msg, msgLen, url, &len);
	msg->iov[3].iov_len = len - tmplen;

	if (err != SLP_OK)
		goto error;

	/* Add tag list */
	msg->iov[6].iov_base = msg->msg + len;
	tmplen = len;

	err = slp_add_string(msg->msg, msgLen, ids, &len);

	if (err != SLP_OK)
		goto error;

	/* SPI string */
	err = slp_add_string(msg->msg, msgLen, spi, &len);

	msg->iov[6].iov_len = len - tmplen;

	hp->fid = ATTRRQST;
	if (err == SLP_OK) {
		return (SLP_OK);
	}

	/* else error */
error:
	free(msg->iov);
	free(msg->msg);

	return (err);
}

SLPError slp_packAttrRqst_single(const char *url,
				const char *scopes,
				const char *ids,
				char **msg,
				const char *lang) {
	SLPError err;
	size_t len, msgLen;

	msgLen =
		SLP_HDRLEN + strlen(lang) + 2 +
		2 + strlen(url) +
		2 + strlen(scopes) +
		2 + strlen(ids) +
		2; /* No SPI string for internal calls */

	if (!(*msg = calloc(msgLen, 1))) {
	    slp_err(LOG_CRIT, 0, "slp_packAttrRqst_single", "out of memory");
	    return (SLP_MEMORY_ALLOC_FAILED);
	}

	len = 0;
	err = slp_add_header(lang, *msg, msgLen, ATTRRQST, msgLen, &len);

	len += 2;	/* empty PR list */

	if (err == SLP_OK) {
	    err = slp_add_string(*msg, msgLen, url, &len);
	}
	if (err == SLP_OK) {
	    err = slp_add_string(*msg, msgLen, scopes, &len);
	}
	if (err == SLP_OK) {
	    err = slp_add_string(*msg, msgLen, ids, &len);
	}
	/* empty SPI */
	if (err == SLP_OK) {
	    err = slp_add_string(*msg, msgLen, "", &len);
	}

	return (err);
}

static int compare_tags(const void *n1, const void *n2) {
	return slp_strcasecmp(
		((struct attr_node *)n1)->tag,
		((struct attr_node *)n2)->tag);
}

static void merge_attrs(struct attr_node *n, char *vals) {
	char *p, *v;

	for (p = v = vals; p; v = p) {
		p = slp_utf_strchr(v, ',');
		if (p)
			*p++ = 0;
		slp_add2list(v, &(n->val), SLP_TRUE);
	}
}

static void parens_attr(char *attr, void **collator, int *numResults) {
	char *open_paren, *close_paren, *equals;
	struct attr_node *n, **res;

	open_paren = attr + 1;
	close_paren = slp_utf_strchr(open_paren, ')');
	if (!close_paren)
		return;	/* skip bad attr list */

	*close_paren = 0;
	if (!(equals = slp_utf_strchr(open_paren, '=')))
		return;

	*equals++ = 0;

	if (!(n = malloc(sizeof (*n)))) {
		slp_err(LOG_CRIT, 0, "collate_attrs", "out of memory");
		return;
	}

	if (!(n->tag = strdup(open_paren))) {
		free(n);
		slp_err(LOG_CRIT, 0, "collate_attrs", "out of memory");
		return;
	}
	n->val = NULL;

	res = slp_tsearch(n, collator, compare_tags);

	if (*res != n) {
		merge_attrs(*res, equals);
		free(n->tag); free(n);
	} else {
		/* not found; populate new attr node */
		(*numResults)++;
		if (!(n->val = strdup(equals))) {
			slp_err(LOG_CRIT, 0, "collate_attrs", "out of memory");
			return;
		}
	}
}

static void collate_attrs(char *attrs, void **collator,
				int *numResults, int maxResults) {
	char *start, *end;
	struct attr_node *n, **res;

	for (start = attrs;
			start &&
			*start &&
			*numResults != maxResults;
						start = end) {
		if (*start == ',') start++;
		if (*start == '(') {
			/* form of (tag=val,val) */
			if (!(end = slp_utf_strchr(start, ')')))
				return;		/* skip bad attr */
			parens_attr(start, collator, numResults);
			end++;
			continue;
		}
		end = slp_utf_strchr(start, ',');
		if (end)
			*end++ = 0;
		/* create a new node with the tag only */
		if (!(n = malloc(sizeof (*n)))) {
			slp_err(LOG_CRIT, 0, "collate_attrs", "out of memory");
			return;
		}

		if (!(n->tag = strdup(start))) {
			free(n);
			slp_err(LOG_CRIT, 0, "collate_attrs", "out of memory");
			return;
		}
		n->val = NULL;
		res = slp_tsearch(n, collator, compare_tags);
		if (*res != n) {
			/* already in the tree, so just free resources */
			free(n->tag); free(n);
		}
		(*numResults)++;
	}
}

static char *build_attrs_list(void *collator) {
	char *answer = NULL;

	if (!collator)
		return (NULL);

	slp_twalk(collator, collect_attrs, 0, &answer);
	return (answer);
}

/*ARGSUSED*/
static void collect_attrs(void *node, VISIT order, int level, void *cookie) {
	struct attr_node *n;
	char *attr, *p, **answer = (char **)cookie;

	if (order == endorder || order == leaf) {
		n = *(struct attr_node **)node;
		if (!n->val) {
			/* no values, so no parens */
			if (!(attr = malloc(strlen(n->tag) + 1))) {
				slp_err(LOG_CRIT, 0, "collect_attrs",
					"out of memory");
				return;
			}
			(void) strcpy(attr, n->tag);
		} else {
			if (!(attr = malloc(1 + strlen(n->tag) + 1 +
					    strlen(n->val) + 2))) {
				slp_err(LOG_CRIT, 0, "collect_attrs",
					"out of memory");
				return;
			}
			/* build attr string */
			p = attr;
			*p++ = '(';
			(void) strcpy(p, n->tag); p += strlen(n->tag);
			*p++ = '=';
			(void) strcpy(p, n->val); p += strlen(n->val);
			*p++ = ')'; *p = 0;
		}

		slp_add2list(attr, answer, SLP_FALSE);
		free(attr);
		free(n->tag); if (n->val) free(n->val); free(n);
		free(node);
	}
}
