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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <slp-internal.h>

/*
 * URL parsing
 */

#define	SLP_IANA	"iana"
#define	SERVICE_PREFIX	"service"

/* service type struct */
typedef struct slp_type {
	SLPBoolean isServiceURL;
	char *atype;
	char *ctype;
	char *na;
	char *orig;
} slp_type_t;

static SLPError parseType(char *, slp_type_t *);
static int validateTypeChars(char *);
static int validateTransport(char *);
static int checkURLString(char *);

SLPError SLPParseSrvURL(char *pcSrvURL, SLPSrvURL** ppSrvURL) {
	char *p, *q, *r;
	SLPSrvURL *surl;
	slp_type_t type[1];

	if (!pcSrvURL || !ppSrvURL) {
		return (SLP_PARAMETER_BAD);
	}

	*ppSrvURL = NULL;
	if (!checkURLString((char *)pcSrvURL))
		return (SLP_PARSE_ERROR);

	if (!(surl = malloc(sizeof (*surl)))) {
		slp_err(LOG_CRIT, 0, "SLPParseSrvURL", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}
	*ppSrvURL = surl;
	surl->s_pcSrvType = "";
	surl->s_pcNetFamily = "";
	surl->s_pcHost = "";
	surl->s_iPort = 0;
	surl->s_pcSrvPart = "";

	/* parse type */
	p = strstr(pcSrvURL, ":/");
	if (!p)
		goto error;
	q = pcSrvURL;
	*p++ = 0; p++;
	r = strdup(q);
	if (parseType(r, type) != SLP_OK)
	goto error;
	free(r);
	/* no need to free type since it is on the stack */
	surl->s_pcSrvType = q;

	/* do we have a transport? */
	q = strchr(p, '/');
	if (!q)
		goto error;
	*q++ = 0;
	if (!validateTransport(p))
		goto error;
	surl->s_pcNetFamily = p;	/* may be \0 */

	/* host part */
	/* do we have a port #? */
	p = strchr(q, ':');
	r = strchr(q, '/');
	if (!p && !r) {	/* only host part */
		surl->s_pcHost = q;
		return (SLP_OK);
	}
	if (p && !r) {	/* host + port, no URL part */
		int port;
		surl->s_pcHost = q;
		*p++ = 0;
		port = atoi(p);
		if (port <= 0)
			goto error;
		surl->s_iPort = port;
		return (SLP_OK);
	}
	*r++ = 0;
	if (!p || p > r) {	/* no port */
		surl->s_pcHost = q;
	} else {		/* host + port + url part */
		int port;
		surl->s_pcHost = q;
		*p++ = 0;
		port = atoi(p);
		if (port <= 0)
			goto error;
		surl->s_iPort = port;
	}

	/* r now points to the URL part */
	surl->s_pcSrvPart = r;

	return (SLP_OK);

error:
	free(surl);
	*ppSrvURL = NULL;
	return (SLP_PARSE_ERROR);
}

/*
 * typeString contains only the service type part of an URL. It should
 * point to a string which parseType can destructively modify.
 */
static SLPError parseType(char *typeString, slp_type_t *type) {
	char *p, *q;

	/* Initialize type structure */
	type->isServiceURL = SLP_FALSE;
	type->atype = NULL;
	type->ctype = NULL;
	type->na = NULL;
	type->orig = typeString;

	if (!validateTypeChars(typeString))
		return (SLP_PARSE_ERROR);

	/* Is this a service: URL? */
	p = strchr(typeString, ':');
	if (strncasecmp(
		typeString, SERVICE_PREFIX, strlen(SERVICE_PREFIX)) == 0) {
		type->isServiceURL = SLP_TRUE;
		if (!p)
			return (SLP_PARSE_ERROR);
		*p++ = 0;
	} else {
		if (p)	/* can't have an abstract type in a non-service url */
			return (SLP_PARSE_ERROR);
		p = typeString;
	}

	/* p now points to the beginning of the type */
	/* is this an abstract type? */
	q = strchr(p, ':');
	if (q) {
		type->atype = p;
		*q++ = 0;
		if (!*p)
			return (SLP_PARSE_ERROR);
	} else { q = p; }

	/* q should now point to the concrete type */
	/* is there a naming authority? */
	p = strchr(q, '.');
	if (p) {
		*p++ = 0;
		if (!*p)
			return (SLP_PARSE_ERROR);
		type->na = p;
	}
	if (!*q)
		return (SLP_PARSE_ERROR);
	type->ctype = q;

	return (SLP_OK);
}

static int validateTransport(char *t) {
	if (*t == 0 ||
	    strcasecmp(t, "ipx") == 0 ||
	    strcasecmp(t, "at") == 0)
		return (1);
	return (0);
}

static int checkURLString(char *s) {
	int i;
	size_t l = strlen(s);
	for (i = 0; i < l; i++) {
		if (isalnum(s[i]) ||
		    s[i] == '/' || s[i] == ':' || s[i] == '-' ||
		    s[i] == ':' || s[i] == '.' || s[i] == '%' ||
		    s[i] == '_' || s[i] == '\''|| s[i] == '*' ||
		    s[i] == '(' || s[i] == ')' || s[i] == '$' ||
		    s[i] == '!' || s[i] == ',' || s[i] == '+' ||
		    s[i] == '\\'|| s[i] == ';' || s[i] == '@' ||
		    s[i] == '?' || s[i] == '&' || s[i] == '=')
			continue;
		return (0);
	}

	return (1);
}


static int validateTypeChars(char *s) {
	int i;
	size_t l = strlen(s);
	for (i = 0; i < l; i++)
		if (!isalnum(s[i]) &&
		    s[i] != '-' &&
		    s[i] != '+' &&
		    s[i] != '.' &&
		    s[i] != ':')
			return (0);
	return (1);
}
