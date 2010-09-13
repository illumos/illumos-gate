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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

static void mdesc_free(void *bufp, size_t size);
uint64_t *md_bufp;

md_t *
mdesc_devinit(void)
{
	int fd;
	md_t *mdp;
	size_t size;

	/*
	 * We haven't finished using the previous MD/PRI info.
	 */
	if (md_bufp != NULL)
		return (NULL);

	do {
		if ((fd = open(MDESC_PATH, O_RDONLY, 0)) < 0)
			break;

		if (ioctl(fd, MDESCIOCGSZ, &size) < 0)
			break;
		if ((md_bufp = (uint64_t *)malloc(size)) == NULL) {
			(void) close(fd);
			break;
		}

		/*
		 * A partial read is as bad as a failed read.
		 */
		if (read(fd, md_bufp, size) != size) {
			free(md_bufp);
			md_bufp = NULL;
		}

		(void) close(fd);
	/*LINTED: E_CONSTANT_CONDITION */
	} while (0);

	if (md_bufp) {
		mdp = md_init_intern(md_bufp, malloc, mdesc_free);
		if (mdp == NULL) {
			free(md_bufp);
			md_bufp = NULL;
		}
	} else
		mdp = NULL;

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
