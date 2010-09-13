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

/*
 * Implements SLPGetRefreshInterval. This call is an AttrRqst with
 * the special service type service:directory-agent.sun, sent
 * only to slpd via loopback, so it mimics the course of a normal
 * SLPFindAttrs call but reroutes the message to slpd.
 */

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <slp-internal.h>

static SLPBoolean refresh_interval_cb(SLPHandle, const char *,
					SLPError, void *);

unsigned short SLPGetRefreshInterval() {
	slp_handle_impl_t *hp;	/* SLP handle for this request */
	SLPError err;		/* any SLPError */
	char *reply = NULL;	/* reply from slpd */
	void *collator = NULL;	/* attr collation handle */
	int mr = 0;		/* max results placeholder */
	unsigned short max = 0;	/* max interval result cookie */
	char *msg = NULL;	/* attrrqst msg */
	char hostname[MAXHOSTNAMELEN];	/* name of this host */

	if ((err = SLPOpen("en", SLP_FALSE, (void **)&hp)) != SLP_OK) {
	    slp_err(LOG_INFO, 0, "SLPGetRefreshInterval",
		    "Could not get SLPHandle: %s", slp_strerror(err));
	    return (0);
	}

	/* tag this as an internal call */
	hp->internal_call = SLP_TRUE;

	/* scope is name of this host */
	(void) gethostname(hostname, MAXHOSTNAMELEN);

	if (slp_packAttrRqst_single(SLP_SUN_DA_TYPE,
				    hostname,
				    "min-refresh-interval",
				    &msg, "en") != SLP_OK) {
	    goto done;
	}

	if (slp_send2slpd(msg, &reply) != SLP_OK) {
	    goto done;
	}

	(void) slp_UnpackAttrReply(hp, reply, refresh_interval_cb,
				    &max, &collator, &mr);

	/* clean up by invoking last call */
	(void) slp_UnpackAttrReply(hp, NULL, refresh_interval_cb,
				    &max, &collator, &mr);

done:
	if (msg) free(msg);
	if (reply) free(reply);

	SLPClose(hp);

	return (max);
}

/*ARGSUSED*/
static SLPBoolean refresh_interval_cb(SLPHandle h, const char *attrs,
					SLPError err, void *cookie) {
	char *p, *next;
	unsigned short *max = (unsigned short *)cookie;

	if (err != SLP_OK) {
	    return (SLP_TRUE);
	}

	p = strchr(attrs, '=');
	if (!p) {
	    *max = 0;
	}

	/* walk through all intervals, looking for the greatest */
	for (p++; p; p = next) {
	    unsigned short anint;

	    next = strchr(p, ',');
	    if (next) {
		*next++ = 0;
	    }

	    anint = (unsigned short)atoi(p);
	    if (anint > *max) {
		*max = anint;
	    }
	}

	return (SLP_TRUE);
}
