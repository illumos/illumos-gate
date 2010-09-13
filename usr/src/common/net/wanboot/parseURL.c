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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <strings.h>
#include <stdlib.h>

#include <parseURL.h>

#define	HTTP_SCHEME	"http://"
#define	HTTPS_SCHEME	"https://"

/*
 * This routine parses a hostport string and initializes an url_hport_t
 * structure with its contents. Technically, a hostport string does not
 * require a port component. In the case, where there is no port component
 * in the hostport string, this routine will initialize the url_hport_t
 * structure with the default port supplied by the caller.
 *
 * A host port string should be of the form -> host[:port]
 *
 * Returns: One of the URL parsing error return codes.
 */
int
url_parse_hostport(const char *hpstr, url_hport_t *hport, ushort_t def_port)
{
	char *lhpstr;
	char *ptr;
	char *optr;
	size_t hlen;

	lhpstr = strdup(hpstr);
	if (lhpstr == NULL) {
		return (URL_PARSE_NOMEM);
	}

	/*
	 * Find the host/port separator.
	 */
	ptr = lhpstr;
	optr = ptr;
	ptr = strstr(optr, ":");
	if (ptr != NULL) {
		*ptr = '\0';
		ptr++;
	}

	/*
	 * Copy in the hostname and check to see that it was a
	 * a valid size.
	 */
	hlen = strlcpy(hport->hostname, optr, sizeof (hport->hostname));
	if (hlen == 0 || hlen >= sizeof (hport->hostname)) {
		free(lhpstr);
		return (URL_PARSE_BAD_HOSTPORT);
	}

	/*
	 * If the hostport string does not contain a port, then use
	 * the default port provided by the caller.
	 */
	if (ptr == NULL || *ptr == '\0') {
		hport->port = def_port;
	} else {
		hport->port = 0;
		while (*ptr != '\0') {
			if (!isdigit(*ptr)) {
				free(lhpstr);
				return (URL_PARSE_BAD_HOSTPORT);
			}
			hport->port *= 10;
			hport->port += (*ptr - '0');
			ptr++;
		}
	}

	free(lhpstr);
	return (URL_PARSE_SUCCESS);
}

/*
 * This routine parses an http or https URL and initializes an url_t
 * structure with its contents.
 *
 * A URL string should be of the form -> http[s]://host[:port]/abspath
 *
 * Returns: One of the URL parsing error return codes.
 */
int
url_parse(const char *urlstr, url_t *url) {

	char *lurlstr;
	char *ptr;
	char *optr;
	size_t plen;
	int ret;

	lurlstr = strdup(urlstr);
	if (lurlstr == NULL) {
		return (URL_PARSE_NOMEM);
	}

	/*
	 * Determine 'http' or 'https'.
	 */
	ptr = lurlstr;
	if (strncmp(ptr, HTTP_SCHEME, strlen(HTTP_SCHEME)) == 0) {
		ptr += strlen(HTTP_SCHEME);
		url->https = B_FALSE;
	} else if (strncmp(ptr, HTTPS_SCHEME, strlen(HTTPS_SCHEME)) == 0) {
		ptr += strlen(HTTPS_SCHEME);
		url->https = B_TRUE;
	} else {
		free(lurlstr);
		return (URL_PARSE_BAD_SCHEME);
	}

	/*
	 * Find the hostport/abspath separator.
	 */
	optr = ptr;
	ptr = strstr(optr, "/");
	if (ptr != NULL) {
		*ptr = '\0';
	}

	/*
	 * Parse the hostport entity; supply suitable port defaults.
	 */
	ret = url_parse_hostport(optr, &url->hport, url->https ?
	    URL_DFLT_HTTPS_SRVR_PORT : URL_DFLT_SRVR_PORT);
	if (ret != URL_PARSE_SUCCESS) {
		free(lurlstr);
		return (ret);
	}

	/*
	 * If the URL string does not contain an abspath, then supply "/"
	 * by default.
	 */
	if (ptr != NULL) {
		*ptr = '/';
		plen = strlcpy(url->abspath, ptr, sizeof (url->abspath));
		if (plen >= sizeof (url->abspath)) {
			free(lurlstr);
			return (URL_PARSE_BAD_ABSPATH);
		}
	} else {
		(void) strlcpy(url->abspath, "/", sizeof (url->abspath));
	}

	free(lurlstr);
	return (URL_PARSE_SUCCESS);
}
