/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#ifndef _URI_H
#define	_URI_H

/* $Id: uri.h 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	scheme://[[user[:password]@]host[:port]]/path[[#fragment]|[?query]]
 */
typedef struct {
	char *scheme;
	char *scheme_part;
	char *user;
	char *password;
	char *host;
	char *port;
	char *path;
	char *fragment;
	char *query;
	/* really for testing, but left in */
	char *user_part;
	char *host_part;
	char *path_part;
} uri_t;

extern int uri_from_string(char *string, uri_t **uri);
extern int uri_to_string(uri_t *uri, char *buffer, size_t buflen);
extern void uri_free(uri_t *uri);

#ifdef __cplusplus
}
#endif

#endif /* _URI_H */
