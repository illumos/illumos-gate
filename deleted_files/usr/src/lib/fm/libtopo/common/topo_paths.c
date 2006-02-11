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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systeminfo.h>
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <fm/libtopo.h>
#include "topo_impl.h"

#define	DEFAULT_DIR	"/usr/lib/fm/topo"

static char pathbuf[MAXPATHLEN];

static char **Topopaths;
static int NTopopaths;

static void
default_paths(void)
{
	char *platform;

	/*
	 *  Probably should make sure it fits, but we're giving it an
	 *  awfully large buffer :-)
	 */
	(void) sysinfo(SI_PLATFORM, pathbuf, MAXPATHLEN);
	platform = topo_strdup(pathbuf);
	(void) snprintf(pathbuf, MAXPATHLEN, "%s/%s", DEFAULT_DIR, platform);
	topo_free(platform);

	NTopopaths = 2;
	Topopaths = topo_zalloc(NTopopaths * sizeof (char *));
	Topopaths[0] = topo_strdup(pathbuf);
	Topopaths[1] = topo_strdup(DEFAULT_DIR);
}

void
topo_paths_init(int npaths, const char **paths)
{
	int i;

	if (paths == NULL) {
		default_paths();
		return;
	}

	NTopopaths = npaths;
	Topopaths = topo_zalloc(NTopopaths * sizeof (char *));

	for (i = 0; i < NTopopaths; i++)
		Topopaths[i] = topo_strdup(paths[i]);
}

void
topo_paths_fini(void)
{
	int i;

	for (i = 0; i < NTopopaths; i++)
		topo_free(Topopaths[i]);
	topo_free(Topopaths);
}

FILE *
topo_open(const char *filename)
{
	FILE *fp = NULL;
	int i;

	for (i = 0; i < NTopopaths; i++) {
		(void) snprintf(pathbuf, MAXPATHLEN, "%s/%s",
		    Topopaths[i], filename);
		if ((fp = fopen(pathbuf, "r")) != NULL)
			break;
		else
			topo_out(TOPO_DEBUG, "%s:", pathbuf);
	}
	return (fp);
}

void *
topo_dlopen(const char *filename)
{
	void *dlp = NULL;
	int i;

	for (i = 0; i < NTopopaths; i++) {
		(void) snprintf(pathbuf, MAXPATHLEN, "%s/%s",
		    Topopaths[i], filename);
		if ((dlp = dlopen(pathbuf, RTLD_LOCAL | RTLD_NOW)) != NULL)
			break;
		else
			topo_out(TOPO_DEBUG, "%s: %s\n", pathbuf, dlerror());
	}
	return (dlp);
}

void
topo_dlclose(void *dlp)
{
	(void) dlclose(dlp);
}

void
topo_close(FILE *fp)
{
	(void) fclose(fp);
}
