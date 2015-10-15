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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sharefs/share.h>
#include "sharetab.h"

/*
 * Get an entry from the share table.
 * There should be at least 4 fields:
 *
 * 	pathname  resource  fstype  options  [ description ]
 *
 * A fifth field (description) is optional.
 *
 * Returns:
 *	> 1  valid entry
 *	= 0  end of file
 *	< 0  error
 */
int
getshare(FILE *fd, share_t **shp)
{
	static char *line = NULL;
	static share_t *sh = NULL;
	char *p;
	char *lasts;
	char *w = " \t";

	if (line == NULL) {
		line = (char *)malloc(MAXBUFSIZE+1);
		if (line == NULL)
			return (-1);
	}
	if (sh == NULL) {
		sh = (share_t *)malloc(sizeof (*sh));
		if (sh == NULL)
			return (-1);
	}

	p = fgets(line, MAXBUFSIZE, fd);
	if (p == NULL)
		return (0);
	line[strlen(line) - 1] = '\0';

	sh->sh_path = (char *)strtok_r(p, w, &lasts);
	if (sh->sh_path == NULL)
		return (-3);
	sh->sh_res = (char *)strtok_r(NULL, w, &lasts);
	if (sh->sh_res == NULL)
		return (-3);
	sh->sh_fstype = (char *)strtok_r(NULL, w, &lasts);
	if (sh->sh_fstype == NULL)
		return (-3);
	sh->sh_opts = (char *)strtok_r(NULL, w, &lasts);
	if (sh->sh_opts == NULL)
		return (-3);
	sh->sh_descr = (char *)strtok_r(NULL, "", &lasts);
	if (sh->sh_descr == NULL)
		sh->sh_descr = "";

	*shp = sh;
	return (1);
}

share_t *
sharedup(share_t *sh)
{
	share_t *nsh;

	nsh = (share_t *)calloc(1, sizeof (*nsh));
	if (nsh == NULL)
		return (NULL);

	if (sh->sh_path) {
		nsh->sh_path = strdup(sh->sh_path);
		if (nsh->sh_path == NULL)
			goto alloc_failed;
	}

	if (sh->sh_res) {
		nsh->sh_res = strdup(sh->sh_res);
		if (nsh->sh_res == NULL)
			goto alloc_failed;
	}
	if (sh->sh_fstype) {
		nsh->sh_fstype = strdup(sh->sh_fstype);
		if (nsh->sh_fstype == NULL)
			goto alloc_failed;
	}
	if (sh->sh_opts) {
		nsh->sh_opts = strdup(sh->sh_opts);
		if (nsh->sh_opts == NULL)
			goto alloc_failed;
	}
	if (sh->sh_descr) {
		nsh->sh_descr = strdup(sh->sh_descr);
		if (nsh->sh_descr == NULL)
			goto alloc_failed;
	}
	return (nsh);

alloc_failed:
	sharefree(nsh);
	return (NULL);
}

void
sharefree(share_t *sh)
{
	if (sh->sh_path != NULL)
		free(sh->sh_path);
	if (sh->sh_res != NULL)
		free(sh->sh_res);
	if (sh->sh_fstype != NULL)
		free(sh->sh_fstype);
	if (sh->sh_opts != NULL)
		free(sh->sh_opts);
	if (sh->sh_descr != NULL)
		free(sh->sh_descr);
	free(sh);
}

/*
 * Return the value after "=" for option "opt"
 * in option string "optlist". Caller must
 * free returned value.
 */
char *
getshareopt(char *optlist, char *opt)
{
	char *p, *pe;
	char *b;
	char *bb;
	char *lasts;
	char *val = NULL;

	b = bb = strdup(optlist);
	if (b == NULL)
		return (NULL);

	while ((p = strtok_r(b, ",", &lasts)) != NULL) {
		b = NULL;
		if ((pe = strchr(p, '=')) != NULL) {
			*pe = '\0';
			if (strcmp(opt, p) == 0) {
				val = strdup(pe + 1);
				goto done;
			}
		}
		if (strcmp(opt, p) == 0) {
			val = strdup("");
			goto done;
		}
	}
done:
	free(bb);
	return (val);
}
