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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* vpinit - initialize vpdirs or update vpdirs based on currentdir */

#include <sys/types.h>
#include <string.h>	/* string functions */
#include <stdlib.h>
#include <stdio.h>	/* stderr */
#include "vp.h"
#include "library.h"

char	**vpdirs;	/* directories (including current) in view path */
int	vpndirs;	/* number of directories in view path */

char	*argv0 = "libvp";	/* command name default for messages */

void
vpinit(char *currentdir)
{
	char	*suffix;	/* path from view path node */
	char	*vpath;		/* VPATH environment variable value */
	char	buf[MAXPATH + 1];
	int	i;
	char	*s;

	/* if an existing directory list is to be updated, free it */
	if (currentdir != NULL && vpndirs > 0) {
		for (i = 0; i < vpndirs; ++i) {
			free(vpdirs[i]);
		}
		free(vpdirs);
		vpndirs = 0;
	}
	/* return if the directory list has been computed */
	/* or there isn't a view path environment variable */
	if (vpndirs > 0 || (vpath = getenv("VPATH")) == NULL ||
	    *vpath == '\0') {
		return;
	}
	/* if not given, get the current directory name */
	if (currentdir == NULL && (currentdir = mygetwd(buf)) == NULL) {
		(void) fprintf(stderr,
		    "%s: cannot get current directory name\n", argv0);
		return;
	}
	/* see if this directory is in the first view path node */
	for (i = 0; vpath[i] == currentdir[i] && vpath[i] != '\0'; ++i) {
		;
	}
	if (i == 0 || (vpath[i] != ':' && vpath[i] != '\0') ||
	    (currentdir[i] != '/' && currentdir[i] != '\0')) {
		return;
	}
	suffix = &currentdir[i];

	/* count the nodes in the view path */
	vpndirs = 1;
	for (s = vpath; *s != '\0'; ++s) {
		if (*s == ':' && *(s + 1) != ':' && *(s + 1) != '\0') {
			++vpndirs;
		}
	}
	/* create the source directory list */
	vpdirs = (char **)mymalloc(vpndirs * sizeof (char *));

	/* don't change VPATH in the environment */
	vpath = stralloc(vpath);

	/* split the view path into nodes */
	for (i = 0, s = vpath; i < vpndirs && *s != '\0'; ++i) {
		while (*s == ':') {	/* ignore null nodes */
			++s;
		}
		vpdirs[i] = s;
		while (*s != '\0' && *++s != ':') {
			if (*s == '\n') {
				*s = '\0';
			}
		}
		if (*s != '\0') {
			*s++ = '\0';
		}
	}
	/* convert the view path nodes to directories */
	for (i = 0; i < vpndirs; ++i) {
		s = mymalloc((strlen(vpdirs[i]) + strlen(suffix) + 1));
		(void) strcpy(s, vpdirs[i]);
		(void) strcat(s, suffix);
		vpdirs[i] = s;
	}
	free(vpath);
}
