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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PARSEURL_H
#define	_PARSEURL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	URL_PARSE_SUCCESS		(uint_t)0
#define	URL_PARSE_NOMEM			(uint_t)1
#define	URL_PARSE_BAD_HOSTPORT		(uint_t)2
#define	URL_PARSE_BAD_SCHEME		(uint_t)3
#define	URL_PARSE_BAD_ABSPATH		(uint_t)4

#define	URL_DFLT_SRVR_PORT		(ushort_t)80
#define	URL_DFLT_HTTPS_SRVR_PORT	(ushort_t)443
#define	URL_DFLT_PROXY_PORT		(ushort_t)8080

#define	URL_MAX_STRLEN			MAXPATHLEN * 2
#define	URL_MAX_PATHLEN			MAXPATHLEN
#define	URL_MAX_HOSTLEN			256

typedef struct {
	char		hostname[URL_MAX_HOSTLEN];
	ushort_t	port;
} url_hport_t;

typedef struct {
	boolean_t	https;
	url_hport_t	hport;
	char		abspath[URL_MAX_PATHLEN];
} url_t;

extern int url_parse_hostport(const char *, url_hport_t *, ushort_t);
extern int url_parse(const char *, url_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PARSEURL_H */
