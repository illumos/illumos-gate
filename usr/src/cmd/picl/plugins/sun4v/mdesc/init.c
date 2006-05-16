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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <alloca.h>
#include <sys/stat.h>
#include <malloc.h>
#include <fcntl.h>
#include <syslog.h>
#include <mdesc.h>
#include <string.h>
#include <errno.h>

#define	MDESC_PATH	"/devices/pseudo/mdesc@0:mdesc"
#define	SIZE	8192

static void mdesc_free(void *bufp, size_t size);
uint8_t *md_bufp;

md_t *
mdesc_devinit(void)
{
	int fh;
	int res;
	int size;
	int offset;
	md_t *mdp;

	if (md_bufp != NULL)
		return (NULL);

	fh = open(MDESC_PATH, O_RDONLY, 0);
	if (fh < 0) {
		return (NULL);
	}

	size = SIZE;	/* initial size */
	offset = 0;

	md_bufp = malloc(size);
	if (NULL == md_bufp) {
		return (NULL);
	}

		/* OK read until we get a EOF */

	do {
		int len;

		len = size - offset;

		while (len < SIZE) {
			size += SIZE;
			md_bufp = realloc(md_bufp, size);
			if (NULL == md_bufp)
				return (NULL);
			len = size - offset;
		}

		do {
			res = read(fh, md_bufp + offset, len);
		} while ((res < 0) && (errno == EAGAIN));

		if (res < 0) {
			free(md_bufp);
			return (NULL);
		}

		offset += res;
	} while (res > 0);

	(void) close(fh);

	md_bufp = realloc(md_bufp, offset);
	if (NULL == md_bufp)
		return (NULL);

	mdp = md_init_intern((uint64_t *)md_bufp, malloc, mdesc_free);
	if (NULL == mdp) {
		free(md_bufp);
		return (NULL);
	}

	return (mdp);
}

/*ARGSUSED*/
void
mdesc_free(void *bufp, size_t size)
{
	if (bufp)
		free(bufp);
}

void
mdesc_devfini(md_t *mdp)
{
	if (mdp)
		(void) md_fini(mdp);

	if (md_bufp)
		free(md_bufp);
	md_bufp = NULL;
}
