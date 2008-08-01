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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: uri.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include "uri.h"

static char *
strndup(char *string, size_t length)
{
	char *result = NULL;

	if (length > 0) {
		length++;


		if ((result = calloc(1, length)) != NULL)
			(void) strlcat(result, string, length);
	}

	return (result);
}


/*
 * This will handle the following forms:
 *	scheme:scheme_data
 *	scheme://[[user[:password]@]host[:port]]/path[[#fragment]|[?query]]
 */
int
uri_from_string(char *string, uri_t **uri)
{
	char *ptr;
	uri_t *u;

	if ((string == NULL) || (uri == NULL)) {
		errno = EINVAL;
		return (-1);
	}

	/* find the scheme:scheme_part split */
	if ((ptr = strchr(string, ':')) == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if ((*uri = u = calloc(1, sizeof (*u))) == NULL)
		return (-1);

	u->scheme = strndup(string, ptr - string);

	if ((ptr[1] == '/') && (ptr[2] == '/')) {
		/*
		 * CSTYLED
		 * scheme://[host_part]/[path_part]
		 */
		char *end = NULL, *user = NULL, *host = NULL, *path = NULL;

		string = ptr + 3; /* skip the :// */

		if ((path = end = strchr(string, '/')) == NULL)
			for (end = string; *end != '\0'; end++);

		u->host_part = strndup(string, end - string);

		for (host = string; host < end; host ++)
			if (*host == '@') {
				/* string to host is the user part */
				u->user_part = strndup(string, host-string);
				/* host+1 to end is the host part */
				u->host_part = strndup(host + 1,
							end - (host+1));
				user = string;
				host++;
				break;
			}

		if (user != NULL) {
			char *password  = NULL;

			for (password = user; (password < host - 1); password++)
				if (*password == ':') {
					u->password = strndup(password + 1,
							host - password - 2);
					break;
				}
			u->user = strndup(user, password - user);
		} else
			host = string;

		if (host != NULL) {
			char *port  = NULL;

			for (port = host; (port < path); port++)
				if ((*port == ':') || (*port == '/'))
					break;

			if (port < path) {
				u->port = strndup(port + 1, path - port - 1);
			}

			u->host = strndup(host, port - host);
		}

		if (path != NULL) {
			char *name = strrchr(path, '/');

			u->path_part = strdup(path);

			if (name != NULL) {
				char *query, *fragment;

				query = strrchr(name, '?');
				if ((query != NULL) && (*query != '\0')) {
					u->query = strdup(query + 1);
					end = query;
				} else
					for (end = path; *end != '\0'; end++);

				fragment = strrchr(name, '#');
				if ((fragment != NULL) && (*fragment != '\0')) {
					u->fragment = strndup(fragment + 1,
							end - fragment - 1);
					end = fragment;
				}

				u->path = strndup(path, end - path);
			}
		}
	} else {	/* scheme:scheme_part */
		u->scheme_part = strdup(&ptr[1]);
	}

	if ((u->host_part == NULL) && (u->path_part == NULL) &&
	    (u->scheme_part == NULL)) {
		errno = EINVAL;
		uri_free(u);
		*uri = NULL;
		return (-1);
	}

	return (0);
}

int
uri_to_string(uri_t *uri, char *buffer, size_t buflen)
{
	if ((uri == NULL) || (buffer == NULL) || (buflen == 0) ||
	    (uri->scheme == NULL) ||
	    ((uri->password != NULL) && (uri->user == NULL)) ||
	    ((uri->user != NULL) && (uri->host == NULL)) ||
	    ((uri->port != NULL) && (uri->host == NULL)) ||
	    ((uri->fragment != NULL) && (uri->path == NULL)) ||
	    ((uri->query != NULL) && (uri->path == NULL))) {
		errno = EINVAL;
		return (-1);
	}

	(void) memset(buffer, 0, buflen);

	if (uri->scheme_part == NULL) {
		(void) snprintf(buffer, buflen,
				"%s://%s%s%s%s%s%s%s%s%s%s%s%s%s",
				uri->scheme,
				(uri->user ? uri->user : ""),
				(uri->password ? ":" : ""),
				(uri->password ? uri->password : ""),
				(uri->user ? "@": ""),
				(uri->host ? uri->host : ""),
				(uri->port ? ":" : ""),
				(uri->port ? uri->port : ""),
				(uri->path[0] != '/' ? "/" : ""), uri->path,
				(uri->fragment ? "#" : ""),
				(uri->fragment ? uri->fragment : ""),
				(uri->query ? "?" : ""),
				(uri->query ? uri->query : ""));
	} else {
		(void) snprintf(buffer, buflen, "%s:%s", uri->scheme,
				uri->scheme_part);
	}

	return (0);
}

void
uri_free(uri_t *uri)
{
	if (uri != NULL) {
		if (uri->scheme != NULL)
			free(uri->scheme);
		if (uri->scheme_part != NULL)
			free(uri->scheme_part);
		if (uri->user != NULL)
			free(uri->user);
		if (uri->password != NULL)
			free(uri->password);
		if (uri->host != NULL)
			free(uri->host);
		if (uri->port != NULL)
			free(uri->port);
		if (uri->path != NULL)
			free(uri->path);
		if (uri->fragment != NULL)
			free(uri->fragment);
		if (uri->query != NULL)
			free(uri->query);
		/* help me debug */
		if (uri->user_part != NULL)
			free(uri->user_part);
		if (uri->host_part != NULL)
			free(uri->host_part);
		if (uri->path_part != NULL)
			free(uri->path_part);
		free(uri);
	}
}

#ifdef DEADBEEF
static void
uri_dump(FILE *fp, uri_t *uri)
{
	if (uri != NULL) {
		fprintf(fp, "URI:\n");
		if (uri->scheme != NULL)
			fprintf(fp, "scheme: %s\n", uri->scheme);
		if (uri->scheme_part != NULL)
			fprintf(fp, "scheme_part: %s\n", uri->scheme_part);
		if (uri->user != NULL)
			fprintf(fp, "user: %s\n", uri->user);
		if (uri->password != NULL)
			fprintf(fp, "password: %s\n", uri->password);
		if (uri->host != NULL)
			fprintf(fp, "host: %s\n", uri->host);
		if (uri->port != NULL)
			fprintf(fp, "port: %s\n", uri->port);
		if (uri->path != NULL)
			fprintf(fp, "path: %s\n", uri->path);
		if (uri->fragment != NULL)
			fprintf(fp, "fragment: %s\n", uri->fragment);
		if (uri->query != NULL)
			fprintf(fp, "query: %s\n", uri->query);
		/* help me debug */
		if (uri->user_part != NULL)
			fprintf(fp, "user_part: %s\n", uri->user_part);
		if (uri->host_part != NULL)
			fprintf(fp, "host_part: %s\n", uri->host_part);
		if (uri->path_part != NULL)
			fprintf(fp, "path_part: %s\n", uri->path_part);
		fflush(fp);
	}
}

int
main(int argc, char *argv[])
{
	uri_t *u = NULL;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s uri\n", argv[0]);
		exit(1);
	}

	if (uri_from_string(argv[1], &u) == 0) {
		char buf[BUFSIZ];

		uri_dump(stdout, u);
		uri_to_string(u, buf, sizeof (buf));
		fprintf(stdout, "reconstituted: %s\n", buf);

		uri_to_string(u, buf, 12);
		fprintf(stdout, "reconstituted(12): %s\n", buf);
	} else
		printf(" failed for %s  (%s)\n", argv[1], strerror(errno));

	exit(0);
}
#endif /* DEADBEEF */
