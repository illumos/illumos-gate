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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sharetab.h"

static int logging_specified(char *);

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
getshare(fd, shp)
	FILE *fd;
	struct share **shp;
{
	static char *line = NULL;
	static struct share *sh = NULL;
	char *p;
	char *lasts;
	char *w = " \t";

	if (line == NULL) {
		line = (char *)malloc(MAXBUFSIZE+1);
		if (line == NULL)
			return (-1);
	}
	if (sh == NULL) {
		sh = (struct share *)malloc(sizeof (*sh));
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

/*
 * Append an entry to the sharetab file.
 */
int
putshare(fd, sh)
	FILE *fd;
	struct share *sh;
{
	int r;

	if (fseek(fd, 0L, 2) < 0)
		return (-1);

	r = fprintf(fd, "%s\t%s\t%s\t%s\t%s\n",
		sh->sh_path,
		sh->sh_res,
		sh->sh_fstype,
		sh->sh_opts,
		sh->sh_descr);
	return (r);
}

/*
 * The entry corresponding to path is removed from the
 * sharetab file.  The file is assumed to be locked.
 * Read the entries into a linked list of share structures
 * minus the entry to be removed.  Then truncate the sharetab
 * file and write almost all of it back to the file from the
 * linked list.
 *
 * If logging information is requested then 'logging' is set
 * to non-zero if the entry is shared with logging enabled.
 *
 * Note: The file is assumed to be locked.
 */
int
remshare(fd, path, logging)
	FILE *fd;
	char *path;
	int *logging;
{
	struct share *sh_tmp;
	struct shl {			/* the linked list */
		struct shl   *shl_next;
		struct share *shl_sh;
	};
	struct shl *shl_head = NULL;
	struct shl *shl, *prev, *next;
	int res, remcnt;

	rewind(fd);
	remcnt = 0;
	shl = NULL;
	while ((res = getshare(fd, &sh_tmp)) > 0) {
		if (strcmp(path, sh_tmp->sh_path) == 0 ||
		    strcmp(path, sh_tmp->sh_res)  == 0) {
			remcnt++;
			if (logging != NULL)
				*logging = logging_specified(sh_tmp->sh_opts);
		} else {
			prev = shl;
			shl = (struct shl *)malloc(sizeof (*shl));
			if (shl == NULL) {
				res = -1;
				goto dealloc;
			}
			if (shl_head == NULL)
				shl_head = shl;
			else
				prev->shl_next = shl;
			shl->shl_next = NULL;
			shl->shl_sh = sharedup(sh_tmp);
			if (shl->shl_sh == NULL) {
				res = -3;
				goto dealloc;
			}
		}
	}
	if (res < 0)
		goto dealloc;
	if (remcnt == 0) {
		res = 1;	/* nothing removed */
		goto dealloc;
	}

	if (ftruncate(fileno(fd), 0) < 0) {
		res = -2;
		goto dealloc;
	}

	for (shl = shl_head; shl; shl = shl->shl_next)
		putshare(fd, shl->shl_sh);
	res = 1;

dealloc:
	for (shl = shl_head; shl; shl = next) {
		/*
		 * make sure we don't reference sharefree with NULL shl->shl_sh
		 */
		if (shl->shl_sh != NULL)
			sharefree(shl->shl_sh);
		next = shl->shl_next;
		free(shl);
	}
	return (res);
}

struct share *
sharedup(sh)
	struct share *sh;
{
	struct share *nsh;

	nsh = (struct share *)malloc(sizeof (*nsh));
	if (nsh == NULL)
		return (NULL);

	(void) memset((char *)nsh, 0, sizeof (*nsh));
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
sharefree(sh)
	struct share *sh;
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
getshareopt(optlist, opt)
	char *optlist, *opt;
{
	char *p, *pe;
	char *b;
	char *bb;
	char *lasts;
	char *val = NULL;

	b = bb = strdup(optlist);
	if (b == NULL)
		return (NULL);

	while (p = (char *)strtok_r(b, ",", &lasts)) {
		b = NULL;
		if (pe = strchr(p, '=')) {
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

/*
 * Return 1 if the "log" option was specified in the optlist.
 * Return 0 otherwise.
 */
static int
logging_specified(optlist)
	char *optlist;
{
	char *p;
	char *b, *bb, *lasts;
	int specified = 0;

	b = bb = strdup(optlist);
	if (b == NULL)
		return (0);

	while (p = (char *)strtok_r(b, ",", &lasts)) {
		b = NULL;
		if (strncmp(p, "log", 3) == 0)
			specified++;
	}

	free(bb);
	return (specified ? 1 : 0);
}
