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
 * DAAdvert functionality. For all normal UA calls, libslp queries
 * slpd for available DAs. This file contains functionality to handle
 * DAAdverts explicitly requested by a call to SLPFindSrvs()
 * or SLPFindAttrs() with service-type = "service:directory-agent".
 */

#include <stdio.h>
#include <slp-internal.h>

SLPError slp_unpackDAAdvert(char *reply, char **surl, char **scopes,
				char **attrs, char **spis, SLPError *errCode) {
	unsigned short protoErrCode, dummy;
	size_t len, off;
	SLPError err = SLP_OK;
	/* authentication components */
	struct iovec iov[5];
	size_t tmp_off;
	int auth_cnt;
	size_t abLen = 0;

	*surl = *scopes = *attrs = *spis = NULL;

	len = slp_get_length(reply);
	off = SLP_HDRLEN + slp_get_langlen(reply);
	/* err code */
	if ((err = slp_get_sht(reply, len, &off, &protoErrCode)) != SLP_OK)
		goto fail;
	/* internal errors should have been filtered out by the net code */
	*errCode = slp_map_err(protoErrCode);
	if (*errCode != SLP_OK) {
		return (SLP_OK);
	}

	/* skip timestamp (4 bytes) */
	iov[0].iov_base = reply + off;
	tmp_off = off;
	if ((err = slp_get_sht(reply, len, &off, &dummy)) != SLP_OK) {
		goto fail;
	}
	if ((err = slp_get_sht(reply, len, &off, &dummy)) != SLP_OK) {
		goto fail;
	}
	iov[0].iov_len = off - tmp_off;

	/* service URL */
	iov[1].iov_base = reply + off;
	tmp_off = off;
	if ((err = slp_get_string(reply, len, &off, surl)) != SLP_OK) {
		goto fail;
	}
	iov[1].iov_len = off - tmp_off;

	/* scopes */
	iov[3].iov_base = reply + off;
	tmp_off = off;
	if ((err = slp_get_string(reply, len, &off, scopes)) != SLP_OK) {
		goto fail;
	}
	iov[3].iov_len = off - tmp_off;

	/* attributes */
	iov[2].iov_base = reply + off;
	tmp_off = off;
	if ((err = slp_get_string(reply, len, &off, attrs)) != SLP_OK) {
		goto fail;
	}
	iov[2].iov_len = off - tmp_off;

	/* SPIs */
	iov[4].iov_base = reply + off;
	tmp_off = off;
	if ((err = slp_get_string(reply, len, &off, spis)) != SLP_OK) {
		goto fail;
	}
	iov[4].iov_len = off - tmp_off;

	/* auth blocks */
	if ((err = slp_get_byte(reply, len, &off, &auth_cnt)) != SLP_OK) {
	    goto fail;
	}
	if (slp_get_security_on() || auth_cnt > 0) {
	    if ((err = slp_verify(iov, 5,
				    reply + off,
				    len - off,
				    auth_cnt,
				    &abLen)) != SLP_OK) {
		goto fail;
	    }
	}

	return (SLP_OK);

fail:
	if (*surl) free (*surl);
	if (*scopes) free (*scopes);
	if (*attrs) free (*attrs);
	if (*spis) free (*spis);

	return (err);
}
